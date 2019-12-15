TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11
SOURCES += \
        connect.c \
        host.c \
        http.c \
        iri.c \
        main.c \
        retr.c \
        url.c \
        utils.c

HEADERS += \
    connect.h \
    host.h \
    http.h \
    iri.h \
    options.h \
    retr.h \
    url.h \
    utils.h \
    wget.h
