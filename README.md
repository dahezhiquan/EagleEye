# EagleEye

鹰眼资产收集管理系统

# 部署流程

1. wget <https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh>

2. sh Miniconda3-latest-Linux-x86\_64.sh

3. vim \~/.bashrc

4. Vim中添加：export PATH="\$PATH:/root/miniconda3/bin"

5. source \~/.bashrc

6. conda --version

7. conda create --name python python=3.8

8. source activate

9. conda deactivate

10. conda activate python

11. apt-get update

12. apt install build-essential libssl-dev libffi-dev python3-dev

13. apt install nmap

14. apt install net-tools

15. apt-get install chromium-browser

16. git clone <https://github.com/dahezhiquan/EagleEye.git>

17. cd EagleEye

18. pip install -r requirements.txt

19. apt install postgresql postgresql-contrib

20. sudo -u postgres psql

21. \password postgres

22. 输入密码两次

23. CREATE DATABASE eagleeye;

24. \q

25. config.py 配置 shodan api key，和数据库连接字符串

26. systemctl restart postgresql

27. systemctl status postgresql

28. sh EagleEye.sh

项目重启步骤： &#x20;
1. conda activate python
2. sh EagleEye_Stop.sh
3. sh EagleEye.sh

设置PostgreSQL远程访问：

1. vim /etc/postgresql/14/main/postgresql.conf

2. 添加：listen\_addresses = '\*'

3. vim /etc/postgresql/14/main/pg\_hba.conf

4. 添加：host all all 0.0.0.0/0 md5

5. service postgresql restart


