unit AccountController;

{$mode objfpc} {$H+}
{$modeswitch advancedrecords} 

interface
	uses
		fgl, Crypto, base64;

	type
		TUserId = qword;
		TUser = record
			userId: TUserId;
			username: string;
			password: string;
			class operator= (const a, b: TUser): Boolean;
		end;
		TUsers = specialize TFPGList<TUser>;

		TAccountManager = class(TObject)
			public
				procedure Initialize;
				function CreateUser(const username: string; const password: string): string;
				function IsAuthorized(const token: string): boolean;
				function GetUserId(const username: string; const password: string): TUserId;
				function GetAuthToken(const userid: TUserId): string;
				function GetListOfUsers(): TUsers;
		end;

	var
		AccountManager: TAccountManager;
implementation

	const
		secret: qword = 0;
	
	procedure TAccountManager.Initialize;
	begin
	end;

	class operator TUser.= (const a, b: TUser): Boolean;
	begin
		result := a.userId = b.userId;
	end;

	function TAccountManager.CreateUser(const username: string; const password: string): string;
	begin
		result := '';
	end;

	function TAccountManager.IsAuthorized(const token: string): boolean;
	var
		tmp: string;
		decoded: pqword;
		len: longint;
	begin
		tmp := DecodeStringBase64(token);
		decoded := pqword(decode(tmp, len));
		result := (len > 16) and (decoded[1] = secret);
	end;

	function TAccountManager.GetUserId(const username: string; const password: string): TUserId;
	begin
		if username = password then
			result := 123456789
		else
			result := 0;
	end;

	function TAccountManager.GetAuthToken(const userid: TUserId): string;
	begin
		result := encodeBlock(@userid);
		result := appendBlock(result, @secret);
		result := EncodeStringBase64(result);
	end;

	function TAccountManager.GetListOfUsers(): TUsers;
	begin
		result := TUsers.Create;
	end;

initialization
	AccountManager := TAccountManager.Create;

end.
