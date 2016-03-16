unit log;

{$H+}

interface
	uses
		configuration;

	procedure debug(const message: string);
	procedure info(const message: string);
	procedure error(const message: string);
	procedure critical(const message: string);

implementation

	uses sysutils, systemlog;

	procedure debug(const message: string);
	begin
		syslog(log_debug, @message[1], []);
	end;
	
	procedure info(const message: string);
	begin
		syslog(log_info, @message[1], []);
	end;

	procedure error(const message: string);
	begin
		syslog(log_err, @message[1], []);
	end;

	procedure critical(const message: string);
	begin
		syslog(log_crit, @message[1], []);
		halt(1);
	end;

	procedure initLog();
	var
		pid: dword;
		prefix: string;
	begin
		pid := getprocessid;
		prefix := format('meters[%d]', [pid]);
		openlog(pchar(prefix), LOG_NOWAIT, LOG_DEBUG);
	end;

initialization

end.
