unit network;

{$H+}

interface
	uses
		Sockets, configuration, baseunix;

	type TConnect = record
		socket: longint;
		address: sockaddr_in;
		length: TSockLen;
	end;

	function accept(): TConnect;
	function recv(const connect: TConnect; const buf: pointer; const size: longint; const timeout: longint): longint;
	function recvByte(const connect: TConnect): byte;
	function recvString(const connect: TConnect): string;
	function send(const connect: TConnect; const data: pointer; const length: longint): boolean;
	function sendString(const connect: TConnect; const data: string): boolean;
	function iptostr(const connect: TConnect): string;

	procedure close(const connect: TConnect);
	
implementation

	uses 
		GSet, GUtil, log, SysUtils;

	var 
		serverSocket: longint;

	function getmessage(const prefix: string): string;
	begin
		getmessage := prefix + inttostr(SocketError);
	end;

	procedure perror(const prefix: string);
	begin
		error(getmessage(prefix));
	end;

	procedure convertIp(var sin_addr: in_addr; const ip: TIp);
	begin
		sin_addr.s_bytes[1] := ip[0];
		sin_addr.s_bytes[2] := ip[1];
		sin_addr.s_bytes[3] := ip[2];
		sin_addr.s_bytes[4] := ip[3];
	end;
	
	procedure initServer(const config: TConfig);
	var 
	    sAddr: sockaddr_in;
	begin
		if serverSocket <> -1 then
			exit;

	    serverSocket := fpSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	    if SocketError <> 0 then
	    	critical(getmessage('socket: '));

	    sAddr.sin_family := AF_INET;
	    sAddr.sin_port := htons(config.port);
		convertIp(sAddr.sin_addr, config.ip);
	    
	    if fpBind(serverSocket, @sAddr, sizeof(sAddr)) = -1 then
	    	critical(getmessage('bind: '));
	    
	    if fpListen(serverSocket, config.backlog) = -1 then
	    	critical(getmessage('listen: '));

		writeln(format('start listening in %d.%d.%d.%d:%d', [config.ip[0], config.ip[1], config.ip[2], config.ip[3], config.port]));
	end;
	
	function accept(): TConnect;
	var
		flags: longint;
	begin
		accept.length := sizeof(accept.address);
	    accept.socket := fpAccept(serverSocket, @accept.address, @accept.length);
	    if accept.socket = -1 then
		begin
	    	perror('accept: ');
			accept.socket := -1;
			exit;
		end;

		flags := fpfcntl(accept.socket, F_GetFL);
		flags := flags or O_NonBlock;
		if fpfcntl(accept.socket, F_SetFL, flags) < 0 then
		begin
			error('can''t set flags for socket');
			accept.socket := -1;
		end;
	end;

	function recv(const connect: TConnect; const buf: pointer; const size: longint; const timeout: longint): longint;
	var
		sel: tpollfd;
		res: longint;
		readed: longint;
	begin
		sel.fd := connect.socket;
		sel.events := POLLIN;
		sel.revents := 0;

		res := fppoll(@sel, 1, timeout);

		if res <= 0 then
		begin
			if res < 0 then
				error('error while poll');
			exit(res);
		end;

		readed := fprecv(connect.socket, buf, size, 0);
		if readed < 0 then
			perror('recv: ');

		exit(readed);
	end;

	function recvByte(const connect: TConnect): byte;
	const
		timeout = 10000;
	var
		res: byte;
	begin
		if recv(connect, @res, 1, timeout) <= 0 then
			exit(255);
		recvByte := res;
	end;

	function recvString(const connect: TConnect): string; 
	const
		size = 255;
		timeout = 1000;
	var
		buffer: string[size];
		readed: longint;
	begin
		readed := recv(connect, @buffer[1], size, timeout);
		if readed <= 0 then
			exit('');
		recvString := copy(buffer, 1, readed);
		while true do
		begin
			readed := recv(connect, @buffer[1], size, 0);
			if readed < 0 then
				exit('');
			if readed = 0 then
				break;
			recvString := recvString + copy(buffer, 1, readed);
		end;
	end;

	function send(const connect: TConnect; const data: pointer; const length: longint): boolean;
	begin
		send := true;
		if fpsend(connect.socket, data, length, 1) = -1 then
		begin
			perror('send: ');
			exit(false);
		end;
	end;

	function sendString(const connect: TConnect; const data: string): boolean;
	begin
		sendString := send(connect, @data[1], length(data));
	end;
	
	function iptostr(const connect: TConnect): string;
	begin
	    iptostr := NetAddrToStr(connect.address.sin_addr);
	end;
	
	procedure close(const connect: TConnect);
	begin
		if closesocket(connect.socket) = -1 then
			perror('close: ');
	end;

initialization
	serverSocket := -1;
	initServer(GetConfig);

finalization
	closesocket(serverSocket);

end.
