unit configuration;


interface
	type TIp = array [0 .. 3] of byte;

	type TConfig = record
		port: word;
		ip: TIp;
		backlog: longint;
	end;

	function GetConfig() : TConfig;

implementation
	
	uses
		log, SysUtils;

	var
		config: TConfig;

	function isDigit(const ch: char): boolean;
	begin
		isDigit := ('0' <= ch) and (ch <= '9');
	end;

	function getint(const s: string): longint;
	var
		i: longint;
	begin
		getint := 0;
		for i := 1 to length(s) do
			if isDigit(s[i]) then
				getint := getint * 10 + ord(s[i]) - 48;
	end;

	function getip(const s: string): TIp;
	var
		i: longint;
		b: byte;
	begin
		fillchar(getip, sizeof(getip), 0);
		b := 0;
		for i := 1 to length(s) do
		begin
			if isDigit(s[i]) then
				getip[b] := getip[b] * 10 + ord(s[i]) - 48;
			if s[i] = '.' then
				b := (b + 1) and 3;
		end;
	end;
	
	procedure load(const fname: string);
	var
	    fin: Text;
	    s: string;
	begin
		if not FileExists(fname) or DirectoryExists(fname) then
			critical('Config file "' + fname + '" doesn''t exist.');

	    assign(fin, fname);
	    reset(fin);
	    while not eof(fin) do
	    begin
	    	readln(fin, s);
	    	s := lowercase(s);
	    	if pos('port', s) = 1 then
	    		config.port := getint(s)
	    	else if pos('ip', s) = 1 then
	    		config.ip := getip(s)
	    	else if pos('backlog', s) = 1 then
	    		config.backlog := getint(s)
	    end;
		close(fin);
	end;

	function GetConfig() : TConfig;
	begin
		GetConfig := config;
	end;

initialization
	load('config');

end.
