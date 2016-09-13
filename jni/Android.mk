LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS += -fPIE -I./src -fexceptions

LOCAL_LDFLAGS += -fPIE -pie -llog

LOCAL_MODULE    := hans

LOCAL_SRC_FILES := ../src/utility.cpp \
../src/exception.cpp \
../src/echo.cpp \
../src/tun.cpp \
../src/tun_dev_linux.c \
../src/sha1.cpp \
../src/main.cpp \
../src/client.cpp \
../src/server.cpp \
../src/auth.cpp \
../src/worker.cpp \
../src/hanstime.cpp


include $(BUILD_EXECUTABLE)
