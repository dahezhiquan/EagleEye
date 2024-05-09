from flask_restful import reqparse, Resource
from flask import session, escape, json

from web import DB
from web.utils.auxiliary import addlog
from web.models import SrcDomain, SrcSubDomain, SrcPorts, SrcUrls, SrcVulnerabilitie
from web.utils.logs import logger


class SrcDomainAPI(Resource):
    """src 主域名任务管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("domain", type=str, location='json')
        self.parser.add_argument("domain_name", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def post(self):
        """添加任务"""
        # 检查用户会话中的状态，如果用户未经授权，则返回 HTTP 状态码 401
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        # 用于转义特殊字符，以防止在处理数据库查询或其他操作时发生错误或安全问题
        key_domain = escape(args.domain.replace('/', ''))
        key_domain_name = escape(args.domain_name)
        if not key_domain or not key_domain_name:
            return {'result': {'status_code': 500}}
        src_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        # 已经存在domain任务
        if src_query:
            addlog(session.get('username'), session.get('login_ip'),
                   f'添加主域名任务失败，主域名为：{key_domain},厂商为:{key_domain_name},原因:该任务已存在')
            return {'result': {'status_code': 201}}
        SrcDomain1 = SrcDomain(domain=key_domain, domain_name=key_domain_name)
        DB.session.add(SrcDomain1)
        try:
            DB.session.commit()
        except Exception as e:
            logger.log('ALERT', '主域名添加任务接口SQL错误:%s' % e)
            DB.session.rollback()
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'),
               f'添加主域名任务成功，主域名为：{key_domain},厂商为:{key_domain_name}')
        logger.log('INFOR', f'添加主域名任务成功-主域名[{key_domain}]-厂商[{key_domain_name}]')
        return {'result': {'status_code': 200}}

    def get(self):
        """查询扫描任务的详情，包括ip数量、子域名数量等"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        # 如果没有查询参数 key_searchParams，则判断是否有分页参数
        # 如果没有分页参数，则默认返回前20个源主域名任务
        # 如果有分页参数，则返回相应分页的任务
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcDomain.query.limit(20).offset(0).all()
            else:
                paginate = SrcDomain.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        # 如果有查询参数 key_searchParams，则尝试解析查询参数
        # 如果解析失败，则默认返回前20个源主域名任务
        # 如果解析成功，则根据查询参数进行查询，并返回相应分页的任务
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcDomain.query.limit(20).offset(0).all()
            else:
                if 'domain' not in search_dict or 'domain_name' not in search_dict:  # 查询参数有误
                    paginate = SrcDomain.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcDomain.query.filter(
                        SrcDomain.domain.like("%" + search_dict['domain'] + "%"),
                        SrcDomain.domain_name.like("%" + search_dict['domain_name'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []

        # 对查询结果进行处理，组装成符合格式的 JSON 数据
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {'id': index, 'domain': i.domain, 'domain_name': i.domain_name, 'domain_time': i.domain_time,
                         'flag': i.flag}
                subdomain_count = len(i.src_subdomain)
                data1['subdomain_count'] = subdomain_count
                if subdomain_count > 0:
                    tmplist = i.src_subdomain
                    data1['ip_count'] = len(tmplist)
                    scan_count = 0
                    cdn_count = 0
                    for tmp in tmplist:
                        if not tmp.flag:
                            scan_count += 1
                        if tmp.cdn:
                            cdn_count += 1
                    data1['scan_count'] = scan_count
                    data1['cdn_count'] = cdn_count
                else:
                    data1['ip_count'] = 0
                    data1['scan_count'] = 0
                    data1['cdn_count'] = 0
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        """删除扫描任务"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = escape(args.domain)
        domain_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if not domain_query:  # 删除的domain不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(domain_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除主任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'删除主任务:[{key_domain}] 成功')
        logger.log('INFOR', f'删除主任务成功，{key_domain}')
        return {'result': {'status_code': 200}}

    def put(self):
        """再次扫描主任务"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_domain = escape(args.domain)
        domain_query = SrcDomain.query.filter(SrcDomain.domain == key_domain).first()
        if not domain_query:  # 删除的domain不存在
            return {'result': {'status_code': 202}}
        domain_query.flag = '未扫描'
        DB.session.add(domain_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'再次扫描主任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'再次扫描主任务:[{key_domain}] 成功')
        logger.log('INFOR', f'再次扫描主任务成功，{key_domain}')
        return {'result': {'status_code': 200}}


class SrcPortsAPI(Resource):
    """src 端口管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        """查询端口信息"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcPorts.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcPorts.query.limit(20).offset(0).all()
            else:
                paginate = SrcPorts.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcPorts.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'product' not in search_dict:  # 查询参数有误
                    paginate = SrcPorts.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcPorts.query.filter(
                        SrcPorts.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcPorts.product.like("%" + search_dict['product'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {'id': index, 'subdomain': i.subdomain, 'subdomain_ip': i.subdomain_ip, 'port': i.port,
                         'service': i.service, 'product': i.product, 'version': i.version, 'porttime': i.port_time,
                         'city': i.src_subdomain.city}
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class SrcSubDomainAPI(Resource):
    """子域名管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        """查询所有的子域名信息"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcSubDomain.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcSubDomain.query.limit(20).offset(0).all()
            else:
                paginate = SrcSubDomain.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcSubDomain.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'subdomain_ip' not in search_dict:  # 查询参数有误
                    paginate = SrcSubDomain.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcSubDomain.query.filter(
                        SrcSubDomain.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcSubDomain.subdomain_ip.like("%" + search_dict['subdomain_ip'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {'id': index, 'domain': i.domain, 'subdomain': i.subdomain, 'domain_ip': i.subdomain_ip,
                         'city': i.city, 'cdn': i.cdn, 'domian_time': i.subdomain_time,
                         'domain_name': i.src_domain.domain_name, 'port_count': len(i.src_ports),
                         'url_count': len(i.src_urls), 'loudong_count': 0}
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class SrcUrlsAPI(Resource):
    """src url扫描任务管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("url_time", type=str, location='json')
        self.parser.add_argument("urls", type=str, location='json')

    def get(self):
        """url扫描任务管理查询"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcUrls.query.filter(SrcUrls.reptile == False).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcUrls.query.filter(SrcUrls.reptile == False).limit(20).offset(0).all()
            else:
                paginate = SrcUrls.query.filter(SrcUrls.reptile == False).limit(key_limit).offset(
                    (key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcUrls.query.filter(SrcUrls.reptile == False).limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcUrls.query.filter(SrcUrls.reptile == False).limit(20).offset(0).all()
                else:
                    paginate1 = SrcUrls.query.filter(
                        SrcUrls.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcUrls.url.like("%" + search_dict['url'] + "%"), SrcUrls.reptile == False)
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {'id': index, 'subdomain': i.subdomain, 'url': i.url, 'title': escape(i.title),
                         'fingerprint': i.fingerprint, 'waf': i.waf, 'reptile': i.reptile, 'w13scan': i.w13scan,
                         'xray': i.xray, 'url_time': i.url_time}
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        """删除URL扫描任务"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.url_time
        url_query = SrcUrls.query.filter(SrcUrls.url_time == key_time).first()
        if not url_query:  # 删除的url不存在
            return {'result': {'status_code': 202}}
        DB.session.delete(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除URL任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'删除URL任务成功')
        logger.log('INFOR', f'删除URL任务成功')
        return {'result': {'status_code': 200}}

    def post(self):
        """添加URL扫描任务"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.url_time
        url_query = SrcUrls.query.filter(SrcUrls.url_time == key_time).first()
        if not url_query:  # 添加的url不存在
            return {'result': {'status_code': 202}}
        url_query.flag = True
        url_query.reptile = True
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'添加URL扫描任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'添加URL扫描任务成功')
        logger.log('INFOR', f'添加URL扫描任务成功')
        return {'result': {'status_code': 200}}

    def put(self):
        """批量添加URL任务"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_scan_dict = args.urls.replace("'", '"')
        try:
            key_scan_dict = json.loads(key_scan_dict)
        except:
            return {'result': {'status_code': 500}}
        for key, value in key_scan_dict.items():
            url_query = SrcUrls.query.filter(SrcUrls.url_time == key_scan_dict[key]['time']).first()
            if not url_query:
                continue
            else:
                url_query.flag = True
                url_query.reptile = True
                DB.session.add(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'批量添加URL任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'批量添加URL任务成功')
        logger.log('INFOR', f'批量添加URL任务成功')
        return {'result': {'status_code': 200}}


class SrcUrls1API(Resource):
    """src url管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        """查询URL"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcUrls.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcUrls.query.limit(20).offset(0).all()
            else:
                paginate = SrcUrls.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcUrls.query.limit(20).offset(0).all()
            else:
                if 'subdomain' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcUrls.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcUrls.query.filter(
                        SrcUrls.subdomain.like("%" + search_dict['subdomain'] + "%"),
                        SrcUrls.url.like("%" + search_dict['url'] + "%"))
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {'id': index, 'subdomain': i.subdomain, 'url': i.url, 'title': escape(i.title),
                         'fingerprint': i.fingerprint, 'waf': i.waf, 'reptile': i.reptile, 'w13scan': i.w13scan,
                         'xray': i.xray, 'url_time': i.url_time}
                index += 1
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class SrcScanAPI(Resource):
    """src 漏洞管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("time", type=str)
        self.parser.add_argument("scan", type=str, location='json')

    def get(self):
        """扫描漏洞查询"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == False).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == False).paginate(1, 20, False).items
            else:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == False).paginate(key_page, key_limit,
                                                                                                    False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == False).paginate(1, 20, False).items
            else:
                if 'plugin' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == False).paginate(key_page,
                                                                                                        key_limit,
                                                                                                        False).items
                else:
                    paginate1 = SrcVulnerabilitie.query.filter(
                        SrcVulnerabilitie.plugin.like("%" + search_dict['plugin'] + "%"),
                        SrcVulnerabilitie.url.like("%" + search_dict['url'] + "%"), SrcVulnerabilitie.flag == False)
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {'id': i.id, 'subdomain': i.subdomain, 'plugin': i.plugin, 'url': escape(i.url),
                         'payload': escape(i.payload), 'raw': i.raw.replace('\n', '<br/>'), 'scan_name': i.scan_name,
                         'time': i.time}
                flag = '未提交'
                if i.flag:
                    flag = '已提交'
                data1['flag'] = flag
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def post(self):
        """提交漏洞到已提交漏洞模块中"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        scan_query.flag = True
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'提交漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}

    def delete(self):
        """删除漏洞"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        DB.session.delete(scan_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}

    def put(self):
        """批量删除漏洞"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_scan_dict = args.scan.replace("'", '"')
        try:
            key_scan_dict = json.loads(key_scan_dict)
        except:
            return {'result': {'status_code': 500}}
        for key, value in key_scan_dict.items():
            url_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_scan_dict[key]['time']).first()
            if not url_query:
                continue
            else:
                DB.session.delete(url_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'批量删除漏洞任务失败,{e}')
            return {'result': {'status_code': 500}}
        addlog(session.get('username'), session.get('login_ip'), f'批量删除漏洞任务成功')
        logger.log('INFOR', f'批量删除漏洞任务成功')
        return {'result': {'status_code': 200}}


class SrcScanSuccessAPI(Resource):
    """src 已提交漏洞管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.parser.add_argument("time", type=str)

    def get(self):
        """已提交漏洞查询"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(1, 20, False).items
            else:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(key_page, key_limit,
                                                                                                   False).items
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(1, 20, False).items
            else:
                if 'plugin' not in search_dict or 'url' not in search_dict:  # 查询参数有误
                    paginate = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.flag == True).paginate(key_page,
                                                                                                       key_limit,
                                                                                                       False).items
                else:
                    paginate1 = SrcVulnerabilitie.query.filter(
                        SrcVulnerabilitie.plugin.like("%" + search_dict['plugin'] + "%"),
                        SrcVulnerabilitie.url.like("%" + search_dict['url'] + "%"), SrcVulnerabilitie.flag == True)
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
                    paginate = paginate1.paginate(key_page, key_limit, False).items

        data = []
        if paginate:
            for i in paginate:
                data1 = {'id': i.id, 'subdomain': i.subdomain, 'plugin': i.plugin, 'url': escape(i.url),
                         'payload': escape(i.payload), 'raw': i.raw.replace('\n', '<br/>'), 'scan_name': i.scan_name,
                         'time': i.time}
                flag = '未提交'
                if i.flag:
                    flag = '已提交'
                data1['flag'] = flag
                data.append(data1)
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        """删除已提交漏洞"""
        if not session.get('status'):
            return {'result': {'status_code': 401}}
        args = self.parser.parse_args()
        key_time = args.time
        scan_query = SrcVulnerabilitie.query.filter(SrcVulnerabilitie.time == key_time).first()
        if not scan_query:
            return {'result': {'status_code': 500}}
        DB.session.delete(scan_query)
        try:
            DB.session.commit()
        except Exception as e:
            DB.session.rollback()
            logger.log('ALERT', f'删除漏洞失败,{e}')
            return {'result': {'status_code': 500}}
        return {'result': {'status_code': 200}}
