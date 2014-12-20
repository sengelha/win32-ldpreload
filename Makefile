TARGET = ldpreload.exe
OBJS = ldpreload.obj

CC = cl.exe
CFLAGS = /nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /c 
LINK = link.exe
LFLAGS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /machine:I386
RM = del

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)
	
$(TARGET): $(OBJS)
	$(LINK) $(LFLAGS) /out:$@ $(OBJS)
