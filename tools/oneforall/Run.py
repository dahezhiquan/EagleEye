import time
import multiprocessing

from web.models import SrcDomain
from web import DB
from web.utils.logs import logger
from tools.oneforall.oneforall import OneForAll


def ReadDomain():
    """读取主域名等待扫描的任务"""
    # 从 SrcDomain 表中选择第一个 flag 不是 '子域名扫描完成' 的记录，并将结果赋给 results 变量
    results = SrcDomain.query.filter(SrcDomain.flag != '子域名扫描完成').first()
    DB.session.commit()
    if results:
        results.flag = '子域名扫描中'
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)
    return results


def WriteDomain(results):
    """修改主域名任务状态"""
    results.flag = '子域名扫描完成'
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', '修改主域名任务状态SQL错误:%s' % e)


def action(domain):
    """子程序执行，开始进行子域名扫描"""
    OneForAll(domain).run()


def main():
    """主方法"""
    # 获取当前进程的名称，并将其赋值给 process_name 变量
    process_name = multiprocessing.current_process().name
    logger.log('INFOR', f'子域名扫描进程启动:{process_name}')
    while True:
        results = ReadDomain()
        # 如果没有获取到任务，程序休眠30秒，再尝试获取
        if not results:
            time.sleep(30)  # 没有任务延迟点时间
        else:
            action(results.domain)
            WriteDomain(results)


if __name__ == '__main__':
    main()
