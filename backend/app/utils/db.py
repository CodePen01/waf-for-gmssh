import asyncio

from sqlalchemy import BLOB, and_, cast, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.utils.logger import logger

DEBUG = False

_Base = declarative_base()


class Base(_Base):
    __abstract__ = True  # 不映射到数据库表
    __table_initialized__ = False  # 不初始化表
    extend_existing = True  # 不覆盖表

    @classmethod
    def get_session(cls):
        dbpath = cls.__dbpath__

        if not dbpath:
            raise Exception("数据库路径不能为空")

        dbpath = f"sqlite+aiosqlite:///{dbpath}"
        engine = create_async_engine(
            dbpath,
            echo=DEBUG,
            connect_args={"check_same_thread": False},
            pool_size=1,  # 单线程协程场景，设为1即可（完全避免锁竞争）
            max_overflow=0,
            pool_recycle=-1,
            pool_pre_ping=False,
        )

        try:
            Session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        except Exception:
            logger.print_exc()
            raise Exception("数据库连接失败")

        return Session()

    @classmethod
    async def page(cls, page=1, page_size=10, filters=None, include_keys=None, order=None, callback=None):
        """
        分页查询方法
        :param page: 当前页码
        :param page_size: 每页条数
        :param filters: 过滤条件（SQLAlchemy表达式列表）
        :param include_keys: 返回字段（逗号分隔字符串）
        :param order: 排序表达式（如 Log.id.desc()），默认无排序
        :return: 分页结果
        """
        # 仅保留核心边界值校验
        page = max(page, 1)
        page_size = max(1, min(page_size, 1000))

        # 处理返回字段（无传入则查所有字段）
        include_fields = []
        if include_keys:
            include_fields = [getattr(cls, key.strip()) if key.strip() != "uri" else cast(cls.uri, BLOB).label("uri") for key in include_keys.split(",") if hasattr(cls, key.strip())]
        query = select(*include_fields) if include_fields else select(cls)

        # 拼接过滤条件
        if filters and isinstance(filters, list):
            query = query.where(and_(*filters))

        # 处理排序（无默认排序）
        if order is not None:
            query = query.order_by(order)

        # 统一使用一个会话执行 统计总数 + 查询数据
        async with cls.get_session() as session:
            # 统计总条数
            count_query = select(func.count()).select_from(query.subquery())
            total = (await session.execute(count_query)).scalar() or 0

            # 分页查询数据
            offset = (page - 1) * page_size
            result = await session.execute(query.limit(page_size).offset(offset))
            rows = result.fetchall()

        # 组装返回数据
        items = []
        fields = [key.strip() for key in include_keys.split(",") if hasattr(cls, key.strip())] if include_keys else cls.__table__.columns.keys()
        for row in rows:
            items.append({fields[idx]: row[idx] if fields[idx] != "uri" else row[idx].decode("utf-8", errors="ignore") for idx in range(len(row))})

        if callback:
            result = []
            for item in items:
                callback(item)
                result.append(item)
        else:
            result = items

        # 组装指定格式的返回结果
        res = {
            "list": result,
            "paginate": {
                "page_size": page_size,  # 每页个数
                "total": total,  # 总数
            },
        }
        return res

    @classmethod
    async def query(cls, order=None, filters=None, include_keys=None, first=False, callback=None):
        """
        查询方法 返回所有数据 支持关联查询
        :param order: 排序字段
        :param session:
        :param filters: 过滤条件,列表 例:[DbBase.uuid==uuid, DbBase.deleted==True]
        :param include_keys: to_dict参数 只取某些字段
        :return: dict total 总条数, items 数据列表
        """

        include_fields = []
        if include_keys:
            include_fields = [getattr(cls, key.strip()) for key in include_keys.split(",") if hasattr(cls, key.strip())]
        query = select(*include_fields) if include_fields else select(cls)

        # 拼接过滤条件
        if filters and isinstance(filters, list):
            query = query.where(and_(*filters))

        # 处理排序（无默认排序）
        if order is not None:
            query = query.order_by(order)

        # 统一使用一个会话执行 统计总数 + 查询数据（核心修复）
        async with cls.get_session() as session:
            result = await session.execute(query)
            if first:
                row = result.fetchone()
                if not row:
                    return None
                rows = [row]
            else:
                rows = result.fetchall()

        if not include_keys:
            if first:
                return rows[0][0]
            else:
                return [row[0] for row in rows]

        # 组装返回数据
        items = []
        fields = [key.strip() for key in include_keys.split(",") if hasattr(cls, key.strip())] if include_keys else cls.__table__.columns.keys()
        for row in rows:
            items.append({fields[idx]: row[idx] for idx in range(len(row))})

        if callback:
            result = []
            for item in items:
                callback(item)
                result.append(item)
        else:
            result = items

        return result if not first else result[0]

    @classmethod
    async def get_obj_by_key(cls, value, key="id"):
        """
        通过key搜索value值的实例
        :param value: 搜索的值
        :param session:
        :param key: 搜索的键, 默认为id
        :return:
        """
        cls_key = getattr(cls, key) if key else cls.uuid
        return await cls.query(**{"filters": [cls_key == value], "first": True})

    @classmethod
    async def save_objs(cls, obj_list):
        """
        批量保存实例
        :param obj_list: 类对象的实例列表
        :param session:
        :return:
        """
        async with cls.get_session() as session:
            session.add_all(obj_list)
            await session.flush()
            await session.commit()

    @classmethod
    async def update_objs(cls, values, filters=None):
        """
        更新实例
        :param values: {'key': 'value'} 属性和值的字典
        :param filters: 过滤条件,列表 例:[DbBase.uuid==uuid, DbBase.deleted==True]
        :param session:
        :return:
        """
        filters = filters if isinstance(filters, list) else []
        async with cls.get_session() as session:
            query = update(cls).where(*filters).values(**values)
            await session.execute(query)
            await session.commit()

    @classmethod
    async def delete_objs(cls, filters=None):
        """
        删除实例
        :param filters: 过滤条件,列表 例:[DbBase.uuid==uuid, DbBase.deleted==True]
        :param session:
        :return:
        """
        filters = filters if isinstance(filters, list) else []
        async with cls.get_session() as session:
            query = delete(cls).where(*filters)
            await session.execute(query)
            await session.commit()

    async def save(self):
        """保存数据"""
        try:
            async with self.get_session() as session:
                session.add(self)
                await session.flush()
                await session.commit()
                await session.refresh(self)
                return self
        except Exception:
            logger.print_exc()
            raise Exception("保存数据失败")

    async def delete(self):
        """删除数据"""
        async with self.get_session() as session:
            await session.delete(self)
            await session.commit()
