AUTOMAKE_OPTIONS = foreign
SUBDIRS = libreverse/libreverse
CXXFLAGS = -Wall -std=c++17 -O3 -g
AM_CPPFLAGS = -I"json/include/" -I"libreverse/libreverse/include/"

bin_PROGRAMS = dotnet-analyzer
dotnet_analyzer_SOURCES = dotnet-analyzer.cpp metadata.cpp streams.cpp error.cpp method.cpp disasm.cpp
dotnet_analyzer_LDFLAGS = -L"libreverse/libreverse/"
dotnet_analyzer_LDADD = -lreverse
