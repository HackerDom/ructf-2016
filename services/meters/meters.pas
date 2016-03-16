program server;

{$H+}

uses
	network, configuration, log, cthreads;

function handler(c: pointer) : ptrint;
var 
	connect: TConnect;
	data: string;
begin
	connect := TConnect(c^);

	info('connected: ' + iptostr(connect));
	while true do
	begin
		data := recv(connect);
		if data = '' then
			break;
		send(connect, data);
	end;
	close(connect);

	handler := 0;
end;

var
	connect: TConnect;

begin
	while true do
	begin
		connect := accept();
		if connect.socket = -1 then
			continue;
		beginthread(@handler, pointer(@connect));
	end;
end.
