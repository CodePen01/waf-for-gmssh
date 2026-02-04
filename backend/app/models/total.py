from sqlalchemy import Column, Integer, String, Text

from app.consts.settings import PATH_WAF_DB_TOTAL
from app.utils.db import Base


class TotalLog(Base):
    __dbpath__ = PATH_WAF_DB_TOTAL
    __tablename__ = "total_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    time = Column(Integer)
    time_localtime = Column(Text)
    server_name = Column(Text)
    ip = Column(Text)
    ip_city = Column(Text)
    ip_country = Column(Text)
    ip_subdivisions = Column(Text)
    ip_continent = Column(Text)
    ip_latitude = Column(Text)
    ip_longitude = Column(Text)
    type = Column(Text)
    url = Column(Text)
    uri = Column(Text)
    user_agent = Column(Text)
    filter_rule = Column(Text)
    incoming_value = Column(Text)
    value_risk = Column(Text)
    http_log = Column(Text)
    http_log_path = Column(Integer)
    zt = Column(Integer)
    gjlx = Column(Integer)
    remark = Column(Text)
    blockade = Column(Integer)
    blocking_time = Column(Integer)
    is_status = Column(Integer)
