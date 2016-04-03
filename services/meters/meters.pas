program server;

{$H+}

uses
	network, configuration, log, cthreads, meterContainer;

procedure sendResults(const connect: TConnect);
var
	results: TMeterResults;
begin
	results := GetAllResults();
	send(connect, @results, sizeof(results));
end;

function handler(c: pointer) : ptrint;
var 
	connect: TConnect;
	command: byte;
	meter: PTMeter;
begin
	connect := TConnect(c^);

	info('connected: ' + iptostr(connect));

	command := recvByte(connect);

	if command < METERS_COUNT then
	begin
		new(meter);
		if recv(connect, meter, sizeof(TMeter), 0) <> sizeof(TMeter) then
			Dispose(meter)
		else
			AddMeterState(command + 1, meter);
		close(connect);
		exit(0);
	end;

	while true do
	begin
		case command of
			128: sendResults(connect);
//			129: sendHistory(connect);
			else break;
		end;
		command := recvByte(connect);
	end;

	close(connect);

	exit(0);
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
