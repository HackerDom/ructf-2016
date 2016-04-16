unit AccountController;

{$mode objfpc} {$H+}
{$modeswitch advancedrecords} 

interface
	uses
		fgl, RC5, SysUtils, Utils, DashboardContainer, avglvltree;

	type
		TUserId = qword;

		TAccountManager = class(TObject)
			private
				users: TStringToPointerTree;
				usersFile: text;
				usersRWSync: TSimpleRWSync;
				usersDashboards: TStringToPointerTree;
				usersDashboardsFile: text;
				usersDashboardsRWSync: TSimpleRWSync;
				procedure InitializeUsersList;
				procedure InitializeUsersDashboardsList;
			public
				procedure Initialize;
				procedure AddDashboard(const userId: TUserId; const dashboardId: TDashboardId);
				function CreateUser(const username: string; const password: string): string;
				function IsAuthorized(const token: string): string;
				function GetUserId(const username: string; const password: string): TUserId;
				function GetAuthToken(const userid: TUserId): string;
				function GetCurrentUserId(const token: string): TUserId;
				function HavePermission(const token: string; const dashboard: TDashboardId): string;
				function AddPermission(const token: string; const dashboardId: TDashboardId): string;
				function GetPermittedDashboards(const token: string): TDashboardIds;
		end;

	var
		AccountManager: TAccountManager;

implementation

	type
		TUser = record
			userId: TUserId;
			password: string;
			class operator= (const a, b: TUser): Boolean;
		end;
		PUser = ^TUser;
		PDashboardIds = ^TDashboardIds;


	var
		ttl: qword;


	procedure TAccountManager.InitializeUsersList;
	var
		filename: unicodestring;
		tmpUser: PUser;
		username: string;
	begin
		writeln(stderr, 'load users');
		flush(stderr);
		usersRWSync := TSimpleRWSync.Create;
		users := TStringToPointerTree.Create(false);

		filename := writeDir + 'users';
		assign(usersFile, filename);
		if FileExists(filename) then
		begin
			reset(usersFile);
			while not seekeof(usersFile) do
			begin
				new(tmpUser);
				readln(usersFile, tmpUser^.userId);
				readln(usersFile, username);
				readln(usersFile, tmpUser^.password);
				users[username] := tmpUser;
			end;
			append(usersFile)
		end
		else
			rewrite(usersFile);
	end;

	procedure TAccountManager.InitializeUsersDashboardsList;
	var
		filename: unicodestring;
		tmpuserid: TUserId;
		suserid: string;
		tmpDashboard: TDashboardId;
	begin
		writeln(stderr, 'load user''s dashboards');
		flush(stderr);
		usersDashboardsRWSync := TSimpleRWSync.Create;
		usersDashboards := TStringToPointerTree.Create(true);

		filename := writeDir + 'usersdashboards';
		assign(usersDashboardsFile, filename);
		if FileExists(filename) then
		begin
			reset(usersDashboardsFile);
			while not seekeof(usersDashboardsFile) do
			begin
				read(usersDashboardsFile, tmpuserid, tmpDashboard);
				suserid := inttostr(tmpuserid);
				if not usersdashboards.contains(suserid) then
					usersdashboards[suserid] := TDashboardIds.Create;
				TDashboardIds(usersDashboards[suserid]).add(tmpDashboard);
			end;
			append(usersDashboardsFile);
		end
		else
			rewrite(usersDashboardsFile);
	end;
	
	procedure TAccountManager.Initialize;
	begin
		writeln(stderr, 'Initialize AccountManager');
		flush(stderr);
		InitializeUsersList;
		InitializeUsersDashboardsList;
	end;

	class operator TUser.= (const a, b: TUser): Boolean;
	begin
		result := a.userId = b.userId;
	end;
	
	function TAccountManager.CreateUser(const username: string; const password: string): string;
	var
		was: boolean;
		user: PUser;
	begin
		if HasBadSymbols(username) or HasBadSymbols(password) then
			exit('username and password must contains symbols with codes from [32 .. 127]');

		usersRWSync.beginread;
		try
			was := users.contains(username);
		finally
			usersRWSync.endread;
		end;

		if was then
			exit('username has already used');

		new(user);
		user^.userId := GetGuid;
		user^.password := password;

		usersRWSync.beginWrite;
		try
			writeln(usersFile, user^.userId);
			writeln(usersFile, username);
			writeln(usersFile, user^.password);
			flush(usersFile);
			users[username] := user;
		finally
			usersRWSync.endWrite;
		end;
	end;

	function TAccountManager.IsAuthorized(const token: string): string;
	var
		decoded: TList;
		dt: qword;
	begin
		decoded := decode(token);
		if decoded.Count = 0 then
		begin
			decoded.free;
			exit('can''t find set time');
		end;
		dt := decoded[0];
		decoded.free;
		if sabs(dt, tsnow) > ttl then
			exit('cookie is too old. set at ' + inttostr(dt));
		result := '';
	end;

	function TAccountManager.GetUserId(const username: string; const password: string): TUserId;
	var
		user: PUser;
	begin
		result := 0;
		usersRWSync.beginread;
		try
			user := users[username];
		finally
			usersRWSync.endread;
		end;
		if (user <> nil) and (user^.password = password) then
			result := user^.userid;
	end;

	function TAccountManager.GetAuthToken(const userid: TUserId): string;
	var
		dashboards: TDashboardIds;
		j: longint;
		dt: qword;
		dashboardId: TDashboardId;
		suserid: string;
	begin
		result := encodeBlock(tsnow);
		result := appendBlock(result, userId);
		suserid := inttostr(userid);
		dashboards := TDashboardIds.Create;

		usersDashboardsRWSync.beginread;
		try
			if usersDashboards.contains(suserid) then
				dashboards.assign(TDashboardIds(usersDashboards[suserid]));
		finally
			usersDashboardsRWSync.endread;
		end;
		for j := 0 to dashboards.Count - 1 do
		begin
			dt := tsnow;
			dashboardId := dashboards[j];
			result := appendBlock(result, dt);
			result := appendBlock(result, dashboardId);
		end;
	end;

	function TAccountManager.GetCurrentUserId(const token: string): TUserId;
	var
		decoded: TList;
	begin
		decoded := decode(token);
		if decoded.Count >= 2 then
			result := decoded[1]
		else
			result := 0;
		decoded.free;
	end;

	function TAccountManager.HavePermission(const token: string; const dashboard: TDashboardId): string;
	var
		decoded: TList;
		i: longint;
		dt: qword;
	begin
		decoded := decode(token);
		for i := 1 to decoded.Count div 2 - 1 do
			if decoded[2 * i + 1] = dashboard then
			begin
				dt := decoded[2 * i];
				decoded.free;
				if sabs(dt, tsnow) > ttl then
					exit('cookie is too old. set at ' + inttostr(dt))
				else
					exit('');
			end;
		result := 'You haven''t permission for this dashboard';
		decoded.free;
	end;

	procedure TAccountManager.AddDashboard(const userId: TUserId; const dashboardId: TDashboardId);
	var
		suserid: string;
	begin
		suserid := inttostr(userid);
		usersDashboardsRWSync.beginWrite;
		try
			writeln(usersDashboardsFile, userid, ' ', dashboardId);
			flush(usersDashboardsFile);
			if not usersDashboards.contains(suserid) then
				usersDashboards[suserid] := TDashboardIds.Create;
			TDashboardIds(usersDashboards[suserid]).add(dashboardId);
		finally
			usersDashboardsRWSync.endWrite;
		end;
	end;

	function TAccountManager.AddPermission(const token: string; const dashboardId: TDashboardId): string;
	var
		dt: qword;
	begin
		dt := tsnow;
		result := appendBlock(token, dt);
		result := appendBlock(result, dashboardId);
	end;

	function TAccountManager.GetPermittedDashboards(const token: string): TDashboardIds;
	var
		decoded: TList;
		i: longint;
	begin
		decoded := decode(token);
		result := TDashboardIds.Create;
		for i := 1 to decoded.Count div 2 - 1 do
			result.add(decoded[2 * i + 1]);
		decoded.free;
	end;

initialization
	writeln(stderr, 'initialization AccountController');
	flush(stderr);
	ttl := 15 * 60;
	AccountManager := TAccountManager.Create;

end.
