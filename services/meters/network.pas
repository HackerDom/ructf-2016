unit network;

{$H+}

interface
	uses
		Sockets, configuration;

	type TConnect = record
		socket: longint;
		address: sockaddr_in;
		length: TSockLen;
	end;

	function accept(): TConnect;
	function recv(const connect: TConnect): string;
	function send(const connect: TConnect; const data: string): boolean;
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
	begin
		accept.length := sizeof(accept.address);
	    accept.socket := fpAccept(serverSocket, @accept.address, @accept.length);
	    if accept.socket = -1 then
		begin
	    	perror('accept: ');
			accept.socket := -1;
			exit;
		end;
	end;

	function recv(const connect: TConnect): string; 
	const
		size = 255;
	var
		buffer: string[size];
		readed: longint;
	begin
		readed := fprecv(connect.socket, @buffer[1], size, 0);
		if readed = -1 then
		begin
			perror('recv: ');
			exit('');
		end;
		recv := copy(buffer, 1, readed);
	end;

	function send(const connect: TConnect; const data: string): boolean;
	begin
		send := true;
		if fpsend(connect.socket, @data[1], length(data), 1) = -1 then
		begin
			perror('send: ');
			exit(false);
		end;
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
