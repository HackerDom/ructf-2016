unit AccountController;

{$mode objfpc}
{$H+}

interface
	type
		TAccountManager = class(TObject)
			public
				procedure Initialize;
				function CreateUser(const username: string; const password: string): string;
				function IsAuthorized(const token: string): boolean;
				function GetUserId(const username: string; const password: string): int64;
				function GetAuthToken(const userid: int64): string;
				function GetListOfUsers(): string;
		end;

	var
		AccountManager: TAccountManager;
implementation
	
	procedure TAccountManager.Initialize;
	begin
	end;


	function TAccountManager.CreateUser(const username: string; const password: string): string;
	begin
		result := '';
	end;

	function TAccountManager.IsAuthorized(const token: string): boolean;
	begin
		result := token = 'authorized';
	end;

	function TAccountManager.GetUserId(const username: string; const password: string): int64;
	begin
		if username = password then
			result := 123456789
		else
			result := 0;
	end;

	function TAccountManager.GetAuthToken(const userid: int64): string;
	begin
		result := 'authorized';
	end;

	function TAccountManager.GetListOfUsers(): string;
	begin
		result := 'empty';
	end;

initialization
	AccountManager := TAccountManager.Create;

end.
