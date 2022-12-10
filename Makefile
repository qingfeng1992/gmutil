
SO_NAME=libgmutil
#OUTPUT_DIR=output
SRC_DIR=src

#加链接参数-Wl,-Bsymbolic 优先使用自己so里面的符号
#加编译参数-fvisibility=hidden 隐藏不必要的符号
#加编译参数--exclude-libs,ALL  隐藏依赖的静态库符号
OFLAGS = -Wl,-rpath=./ -fvisibility=hidden -Wl,-Bsymbolic -Wl,--exclude-libs,ALL
#OFLAGS = -g -Wl,-rpath=./ -fvisibility=hidden -Wl,-Bsymbolic -Wl,--exclude-libs,ALL
#OFLAGS = -Wl,-rpath=./
#包含头文件路径，要加-I
IncludePaths= -I./include
Libs = -lpthread -Llib -lcrypto -lssl -ldl

test:$(SRC_DIR)/test.cpp $(SO_NAME).so
	g++ -std=c++11 $(IncludePaths) -g -Wl,-rpath=./ -L./ -lgmutil $(Libs) -o test $<
$(SO_NAME).so:$(SRC_DIR)/gmutil.cpp
	g++ -std=c++11 $(IncludePaths) -shared -fPIC -o $@ $^ $(OFLAGS) $(Libs)

clean:
	rm -f *.o
	rm -f test
	rm -f $(SO_NAME).so