#CXXFLAGS = -O0 -g3 -Wall -fmessage-length=0 -L -lntl -lm -std=c++0x
#CXXFLAGS = -O2 -g0 -Wall -std=c++0x -pthread -march=native -fmessage-length=0 -L -lntl -lgmp -lgf2x -lm
CXXFLAGS = -O2 -g0 -Wall -std=c++0x -pthread -march=native -fmessage-length=0

# g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm
# -pthread -march=native
# -lgmp -lgf2x


OBJS = md5.o GenericAES.o NTLUtils.o MixingBijections.o WBAES.o WBAESGenerator.o LinearAffineEq.o BGEAttack.o

LIBS = -lntl -lgmp -lm -L/opt/local/lib/ -lboost_iostreams -lboost_serialization -lboost_program_options -lpthread

TARGET = main
TARGET01 = testing

$(TARGET):  $(OBJS) $(TARGET).o
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(TARGET).o $(OBJS) $(LIBS)

$(TARGET01):	$(OBJS) $(TARGET01).o
	$(CXX) $(CXXFLAGS) -o $(TARGET01) $(TARGET01).o $(OBJS) $(LIBS)

all:	$(TARGET) $(TARGET01)

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET01) $(TARGET).o $(TARGET01).o