unit AuthorizeController;

{$mode objfpc}{$H+}

interface
	
	function CreateUser(const username: string; const password: string): string;

	function IsAuthorized(const token: string): boolean;
	function IsCorrectCredentials(const username: string; const password: string): boolean;

	function GetAuthToken(const username: string; const password: string): string;

implementation

	function CreateUser(const username: string; const password: string): string;
	begin
		result := '';
	end;

	function IsAuthorized(const token: string): boolean;
	begin
		result := token = 'authorized';
	end;

	function IsCorrectCredentials(const username: string; const password: string): boolean;
	begin
		result := username = password;
	end;

	function GetAuthToken(const username: string; const password: string): string;
	begin
		result := 'authorized';
	end;

end.
