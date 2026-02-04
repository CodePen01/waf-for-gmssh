from sqlalchemy import BigInteger, Column, Date, Integer, String, Text

from app.consts.settings import PATH_WAF_DB_COUNT
from app.utils.db import Base


class ReqLog(Base):
    __dbpath__ = PATH_WAF_DB_COUNT
    __tablename__ = "t_req_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    time = Column(Integer)
    time_localtime = Column(String)
    date = Column(Date, comment="日期")
    hour = Column(Integer, default=0)
    minute = Column(Integer, default=0)
    server_name = Column(String(64))
    lx = Column(Integer, default=0)
    ll = Column(BigInteger, default=0)


class QsLog(Base):
    # 趋势表
    __dbpath__ = PATH_WAF_DB_COUNT
    __tablename__ = "t_qs_log"

    # 字段完全对齐原表：类型、主键、自增、默认值、拼写(mouth)全部一致
    id = Column(Integer, primary_key=True, autoincrement=True, comment="主键ID")
    date = Column(String, comment="统计日期（年：2026 | 月：2026-01 | 日：2026-01-04）")
    year = Column(Integer, default=0, comment="年份")
    month = Column(Integer, default=0, comment="月份")
    day = Column(Integer, default=0, comment="日期")
    server_name = Column(String(64), comment="服务名称")
    sjlx = Column(Integer, default=0, comment="统计类型：1=年 2=月 3=日")
    qqcs = Column(BigInteger, default=0, comment="请求次数")
    ljcs = Column(BigInteger, default=0, comment="累计次数")
    qqll = Column(BigInteger, default=0, comment="请求流量")
    ljll = Column(BigInteger, default=0, comment="累计流量")
