unit AccountController;

{$mode objfpc} {$H+}
{$modeswitch advancedrecords} 

interface
	uses
		fgl, RC5, SysUtils, Utils, DashboardContainer;

	type
		TUserId = qword;
		TUser = record
			userId: TUserId;
			username: string;
			password: string;
			class operator= (const a, b: TUser): Boolean;
		end;
		TUsers = specialize TFPGList<TUser>;

		TUserDashboards = record
			userid: TUserId;
			dashboards: TDashboardIds;
			class operator= (const a, b: TUserDashboards): Boolean;
		end;

		TUsersDashboards = specialize TFPGList<TUserDashboards>;

		TAccountManager = class(TObject)
			private
				users: TUsers;
				usersFile: text;
				usersRWSync: TSimpleRWSync;
				usersDashboards: TUsersDashboards;
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
				function GetDashboards(const userid: TUserId): TDashboardIds;
				function HavePermission(const token: string; const dashboard: TDashboardId): string;
				function GetUser(const userId: TUserId): TUser;
				function AddPermission(const token: string; const dashboardId: TDashboardId): string;
				function GetPermittedDashboards(const token: string): TDashboardIds;
		end;

	var
		AccountManager: TAccountManager;
implementation

	var
		defaultUser: TUser;
		ttl: TDateTime;


	procedure TAccountManager.InitializeUsersList;
	var
		filename: unicodestring;
		tmpUser: TUser;
	begin
		writeln(stderr, 'load users');
		flush(stderr);
		usersRWSync := TSimpleRWSync.Create;
		users := TUsers.Create;

		filename := writeDir + 'users';
		assign(usersFile, filename);
		if FileExists(filename) then
		begin
			reset(usersFile);
			while not seekeof(usersFile) do
			begin
				readln(usersFile, tmpUser.userId);
				readln(usersFile, tmpUser.username);
				readln(usersFile, tmpUser.password);
				users.add(tmpUser);
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
		tmpDashboard: TDashboardId;
		tmp: TUserDashboards;
		i: longint;
		found: boolean;
	begin
		writeln(stderr, 'load user''s dashboards');
		flush(stderr);
		usersDashboardsRWSync := TSimpleRWSync.Create;
		usersDashboards := TUsersDashboards.Create;

		filename := writeDir + 'usersdashboards';
		assign(usersDashboardsFile, filename);
		if FileExists(filename) then
		begin
			reset(usersDashboardsFile);
			while not seekeof(usersDashboardsFile) do
			begin
				read(usersDashboardsFile, tmpuserid, tmpDashboard);
				found := false;
				for i := 0 to usersDashboards.Count - 1 do
					if usersDashboards[i].userid = tmpuserid then
					begin
						usersDashboards[i].dashboards.add(tmpDashboard);
						found := true;
					end;
				if not found then
				begin
					tmp.userid := tmpuserid;
					tmp.dashboards := TDashboardIds.Create;
					tmp.dashboards.add(tmpDashboard);
					usersDashboards.add(tmp);
				end;
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
	
	class operator TUserDashboards.= (const a, b: TUserDashboards): Boolean;
	begin
		result := a.userid = b.userid;
	end;

	function TAccountManager.CreateUser(const username: string; const password: string): string;
	var
		i: longint;
		was: boolean;
		user: TUser;
	begin
		if HasBadSymbols(username) or HasBadSymbols(password) then
			exit('username and password must contains symbols with codes from [32 .. 127]');

		was := false;
		usersRWSync.beginread;
		for i := 0 to users.Count - 1 do
			was := was or  (users[i].username = username);
		usersRWSync.endread;

		if was then
			exit('username has already used');

		user.userId := GetGuid;
		user.username := username;
		user.password := password;

		usersRWSync.beginWrite;
		writeln(usersFile, user.userId);
		writeln(usersFile, user.username);
		writeln(usersFile, user.password);
		flush(usersFile);
		users.add(user);
		usersRWSync.endWrite;
	end;

	function TAccountManager.IsAuthorized(const token: string): string;
	var
		decoded: TList;
		dt: TDateTime;
	begin
		decoded := decode(token);
		if decoded.Count = 0 then
			exit('can''t find set time');
		dt := unpack(decoded[0]);
		if abs(dt - now) > ttl then
			exit('cookie is too old. set at ' + format('%.10f', [dt]));
		result := '';
	end;

	function TAccountManager.GetUserId(const username: string; const password: string): TUserId;
	var
		i: longint;
	begin
		result := 0;
		usersRWSync.beginread;
		for i := 0 to users.Count - 1 do
			if (users[i].username = username) and (users[i].password = password) then
				result := users[i].userid;
		usersRWSync.endread;
	end;

	function TAccountManager.GetAuthToken(const userid: TUserId): string;
	var
		dashboards: TDashboardIds;
		i, j: longint;
		dt: double;
		dashboardId: TDashboardId;
	begin
		result := encodeBlock(now);
		result := appendBlock(result, userId);

		usersDashboardsRWSync.beginread;
		for i := 0 to usersDashboards.Count - 1 do
		begin
			if usersDashboards[i].userId = userid then
			begin
				dashboards := usersDashboards[i].dashboards;
				for j := 0 to dashboards.Count - 1 do
				begin
					dt := now;
					dashboardId := dashboards[j];
					result := appendBlock(result, dt);
					result := appendBlock(result, dashboardId);
				end;
				break;
			end;
		end;
		usersDashboardsRWSync.endread;
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
	end;

	function TAccountManager.GetDashboards(const userId: TUserId): TDashboardIds;
	var
		i: longint;
	begin
		result := nil;
		usersDashboardsRWSync.beginread;
		for i := 0 to usersDashboards.count - 1 do
		begin
			if usersDashboards[i].userId = userId then
			begin
				result := TDashboardIds.Create;
				result.assign(usersDashboards[i].dashboards);
				break;
			end;
		end;
		usersDashboardsRWSync.endread;
	end;

	function TAccountManager.HavePermission(const token: string; const dashboard: TDashboardId): string;
	var
		decoded: TList;
		i: longint;
		dt: TDateTime;
	begin
		decoded := decode(token);
		for i := 1 to decoded.Count div 2 - 1 do
			if decoded[2 * i + 1] = dashboard then
			begin
				dt := unpack(decoded[2 * i]);
				if abs(dt - now) > ttl then
					exit('cookie is too old. set at ' + format('%.10f', [dt]))
				else
					exit('');
			end;
		result := 'You haven''t permission for this dashboard';
	end;

	function TAccountManager.GetUser(const userId: TUserId): TUser;
	var
		i: longint;
	begin
		result := defaultUser;

		usersRWSync.beginRead;
		for i := 0 to users.count - 1 do
			if users[i].userid = userId then
			begin
				result := users[i];
				break;
			end;
		usersRWSync.endread;
	end;

	procedure TAccountManager.AddDashboard(const userId: TUserId; const dashboardId: TDashboardId);
	var
		userDashboards: TUserDashboards;
		i: longint;
		found: Boolean;
	begin
		usersDashboardsRWSync.beginWrite;
		writeln(usersDashboardsFile, userid, ' ', dashboardId);
		flush(usersDashboardsFile);
		found := false;
		for i := 0 to usersDashboards.Count - 1 do
			if usersDashboards[i].userid = userid then
			begin
				usersDashboards[i].dashboards.add(dashboardId);
				found := true;
				break;
			end;
		if not found then
		begin
			userDashboards.userid := userid;
			userDashboards.dashboards := TDashboardIds.Create;
			userDashboards.dashboards.add(dashboardId);
			usersDashboards.Add(userDashboards);
		end;
		usersDashboardsRWSync.endWrite;
	end;

	function TAccountManager.AddPermission(const token: string; const dashboardId: TDashboardId): string;
	var
		dt: TDateTime;
	begin
		dt := now;
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
	end;

initialization
	writeln(stderr, 'initialization AccountController');
	flush(stderr);
	defaultUser.userid := 0;
	defaultUser.username := 'No user';
	ttl := EncodeTime(23, 59, 59, 999);
	AccountManager := TAccountManager.Create;

end.
