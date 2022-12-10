本项目是基于gmssl封装sm2相关算法，生成gmutil.so动态库，使用时只需要包含头文件gmutil.h和
gmutil.so动态库

使用的gmssl版本是:
GmSSL 2.5.4 - OpenSSL 1.1.0d  19 Jun 2019

封装的成动态库的目的是屏蔽openssl的头文件和符号，避免和其他版本的openssl产生冲突，达到多个
openssl版本共存的目的

目前只封装sm2相关的算法，后续如果想增加其他算法，可以在本项目中直接修改

编译：
直接在本目录执行：make
