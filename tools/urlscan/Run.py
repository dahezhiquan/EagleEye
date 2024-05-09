import requests
import chardet
from bs4 import BeautifulSoup
import random
import ipaddress
from concurrent import futures
import time
import threading
import multiprocessing

from web.models import SrcPorts, SrcUrls
from web import DB
from web.utils.logs import logger
from tools.urlscan.wafw00f.main import main
from config import UrlScan

requests.packages.urllib3.disable_warnings()
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
    'Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']
# 线程锁🔒
LOCK = threading.RLock()


def ReadPort():
    """读取ports表任务"""
    sql_ports_list = SrcPorts.query.filter(SrcPorts.flag == False).limit(UrlScan.threads).all()
    DB.session.commit()
    return sql_ports_list


def WritePort(sql_ports):
    """修改ports表任务"""
    LOCK.acquire()
    sql = SrcPorts.query.filter(SrcPorts.id == sql_ports.id).first()
    DB.session.commit()
    if not sql:
        logger.log('ALERT', f'更新端口信息{sql_ports.id}不存在')
        LOCK.release()
        return
    sql.flag = True
    DB.session.add(sql)
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', f'更新端口ports任务状态SQL错误:{e}')
    finally:
        LOCK.release()


def WirteUrl(url, subdomain, title, fingerprint, waf):
    LOCK.acquire()
    if len(url) > 300:
        LOCK.release()
        return None
    sql_urls = SrcUrls(url=url, subdomain=subdomain, title=title, fingerprint=fingerprint, waf=waf)
    DB.session.add(sql_urls)
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.log('ALERT', f'入库urls任务SQL错误:{e}')
    finally:
        LOCK.release()


def action(sql_ports):
    logger.log('INFOR', f'url开始探测:{sql_ports.subdomain}:{sql_ports.port}')
    response = check_http(sql_ports)
    if response is None:  # 非HTTP服务
        logger.log('INFOR', f'url探测:{sql_ports.subdomain}:{sql_ports.port}非HTTP服务')
        WritePort(sql_ports)
        return None
    if response.status_code in UrlScan.success_status_code:
        mychar = chardet.detect(response.content)
        bianma = mychar['encoding']  # 自动识别编码
        response.encoding = bianma
        title = get_title(markup=response.text)
        banner = get_banner(response.headers)
        # 调用wafw00f探测waf
        falg, waf = main(response.url)
        if not falg:
            waf = ''
        WritePort(sql_ports)
        WirteUrl(response.url, sql_ports.subdomain, title, banner, waf)
        logger.log('INFOR', f'url探测:{response.url}查找完毕')
        return True
    elif response.status_code in UrlScan.failure_status_code:
        WritePort(sql_ports)
        if not UrlScan.subdirectory:
            return None
        logger.log('INFOR', f'url探测:{response.url}开始二级目录查找')
        sucess = sub_path_main(response.url)
        if not sucess:
            logger.log('INFOR', f'url探测:{response.url}二级目录未查找到')
        else:
            logger.log('INFOR', f'url探测:{response.url}二级目录已查找到[{len(sucess)}]个')
            response = sucess[0]
            mychar = chardet.detect(response.content)
            bianma = mychar['encoding']  # 自动识别编码
            response.encoding = bianma
            title = get_title(markup=response.text)
            banner = get_banner(response.headers)
            falg, waf = main(response.url)
            if not falg:
                waf = ''
            WirteUrl(response.url, sql_ports.subdomain, title, banner, waf)
            logger.log('INFOR', f'url探测:二级目录 {response.url}查找完毕')
            return True
    else:
        logger.log('DEBUG', f'url探测:{response.url}为其他状态码[{response.status_code}]')
        WritePort(sql_ports)


def check_http(sql_ports):
    """HTTP服务探测"""
    url = f'http://{sql_ports.subdomain}:{sql_ports.port}'
    headers = gen_fake_header()
    try:
        # 发送 HTTP GET 请求，访问构建的 URL
        response = requests.get(url, timeout=UrlScan.timeout, headers=headers)
    except requests.exceptions.SSLError:
        # SSL验证失败，改用https协议
        url = f'https://{sql_ports.subdomain}:{sql_ports.port}'
        try:
            response = requests.get(url, timeout=UrlScan.timeout, verify=False, headers=headers)
        except Exception as e:
            return None
        else:
            return response
    except Exception as e:
        return None
    else:
        return response


def get_title(markup):
    """获取网页标题"""
    try:
        soup = BeautifulSoup(markup, 'lxml')
    except:
        return None
    title = soup.title
    if title:
        return title.text.strip()
    h1 = soup.h1
    if h1:
        return h1.text.strip()
    h2 = soup.h2
    if h2:
        return h2.text.strip()
    h3 = soup.h3
    if h2:
        return h3.text.strip()
    desc = soup.find('meta', attrs={'name': 'description'})
    if desc:
        return desc['content'].strip()
    word = soup.find('meta', attrs={'name': 'keywords'})
    if word:
        return word['content'].strip()
    if len(markup) <= 200:
        return markup.strip()
    text = soup.text
    if len(text) <= 200:
        return text.strip()
    return None


def get_banner(headers):
    banner = str({'Server': headers.get('Server'),
                  'Via': headers.get('Via'),
                  'X-Powered-By': headers.get('X-Powered-By')})
    return banner


def gen_random_ip():
    """
    生成随机的点分十进制的IP字符串
    """
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2 ** 32 - 1))
        if ip.is_global:
            return ip.exploded


def gen_fake_header():
    """
    生成伪造请求头
    """
    ua = random.choice(user_agents)
    ip = gen_random_ip()
    headers = {
        'Accept': 'text/html,application/xhtml+xml,'
                  'application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'DNT': '1',
        'Referer': 'https://www.google.com/',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
        'X-Forwarded-For': ip,
        'X-Real-IP': ip
    }
    return headers


def urlscan_main():
    """URL探测"""
    process_name = multiprocessing.current_process().name
    logger.log('INFOR', f'可用URL探测进程启动:{process_name}')
    # 创建一个线程池对象 pool，用于管理并发执行的线程
    pool = futures.ThreadPoolExecutor(max_workers=UrlScan.threads)
    while True:
        sql_ports_list = ReadPort()
        if not sql_ports_list:
            time.sleep(30)
        else:
            # 使用线程池对象 pool 并发执行 action 函数，对端口列表中的每个端口执行探测操作
            wait_for = [pool.submit(action, sql_port) for sql_port in sql_ports_list]
            for f in futures.as_completed(wait_for):
                f.result()


def sub_path_main(url):
    """在给定的 URL 上查找二级目录"""
    sub_pool = futures.ThreadPoolExecutor(max_workers=UrlScan.subdirectory_threads)
    wait_for = [sub_pool.submit(sub_chek, url + '/' + path) for path in UrlScan.subdirectory_path]
    sucess = []
    for result in futures.as_completed(wait_for):
        response = result.result()
        if response:
            if response.status_code in UrlScan.success_status_code:
                sucess.append(response)
    sub_pool.shutdown()
    return sucess


def sub_chek(url):
    headers = gen_fake_header()
    try:
        response = requests.get(url, timeout=UrlScan.timeout, verify=False, headers=headers)
    except Exception:
        return None
    else:
        return response


if __name__ == '__main__':
    urlscan_main()
