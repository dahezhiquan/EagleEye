from web.models import User
from web import APP, DB

"""
项目启动地址
"""

'''
创建数据库
'''


def CreateDatabase():
    DB.create_all()


'''
创建测试账户
'''


def CreateUser():
    sql = User.query.filter(User.username == 'root').first()
    if not sql:
        user1 = User(username='root', password='qazxsw@123', name='管理员', phone='18888888888', email='admin@888.com',
                     remark='信息安全工程师')
        DB.session.add(user1)
        DB.session.commit()


def DeletDb():
    """重置数据库"""
    DB.drop_all()
    CreateDatabase()
    CreateUser()


def eagle_eye_main():
    CreateDatabase()
    CreateUser()
    APP.run(host='0.0.0.0', port=APP.config['PORT'])


if __name__ == '__main__':
    eagle_eye_main()
