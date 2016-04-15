unit Utils;

{$mode objfpc}{$H+}

interface

	const
		writeDir = './data/';
		templatesDir = './templates/';
	
	function readFile(const path: string): string;
	function GetGuid: QWord;
	function HasBadSymbols(const s: string): boolean;
	function GetLayout: string;
	function GetLayout(const module, action: string): string;
	function GetTemplate(const module, action: string): string;
	function GetSubTemplate(const module, name: string): string;
	function StrToQWord(const s: string): QWord;
	function htmlEncode(const str: string): string;
	function DateTimeToUnix(dtDate: TDateTime): dword;
	function TSNow: dword;

implementation
	uses
		SysUtils, baseunix;

	const
		UnixStartDate: TDateTime = 25569.0;

	function DateTimeToUnix(dtDate: TDateTime): dword;
	begin
		result := trunc((dtDate - UnixStartDate) * 86400);
	end;

	function TSNow: dword;
	begin
		result := DateTimeToUnix(now);
	end;

	var 
		getGuidLock: TRTLCriticalSection;
		layout: string;

	function readFile(const path: string): string;
	var
		fin: Text;
		tmp: string;
	begin

		writeln(stderr, 'try read "', path, '"');
		flush(stderr);

		assign(fin, path);
		reset(fin);
		result := '';
		while not eof(fin) do
		begin
			readln(fin, tmp);
			result := result + tmp;
		end;
		close(fin);
	end;

	function GetGuid: QWord;
	begin
		EnterCriticalSection(getGuidLock);

		result := random(65536);
		result := (result shl 16) xor random(65536);
		result := (result shl 16) xor random(65536);
		result := (result shl 16) xor random(65536);

		LeaveCriticalSection(getGuidLock);
	end;

	function HasBadSymbols(const s: string): boolean;
	var
		i: longint;
	begin
		result := false;
		for i := 1 to length(s) do
			result := result or (s[i] < #32) or (#127 < s[i]);
	end;

	function GetLayout: string;
	begin
		result := layout; 
	end;

	function GetLayout(const module, action: string): string;
	var
		layout: string;
	begin
		layout := GetLayout();
		result := StringReplace(layout, '{-title-}', module + ': ' + action, []);
	end;

	function GetTemplate(const module, action: string): string;
	var
		layout: string;
		template: string;
	begin
		template := readFile(templatesDir + module + '/' + action);
		layout := GetLayout(module, action);
		result := StringReplace(layout, '{-body-}', template, []);
	end;

	function GetSubTemplate(const module, name: string): string;
	begin
		result := readFile(templatesDir + module + '/' + name);
	end;

	function StrToQWord(const s: string): QWord;
	var
		i: longint;
	begin
		result := 0;
		for i := 1 to length(s) do
		begin
			if (s[i] < '0') or ('9' < s[i]) then
				exit(0);
			result := 10 * result + ord(s[i]) - 48;
		end;
	end;

	function htmlEncode(const str: string): string;
	begin
		result := StringReplace(str, '&', '&amp;', [rfReplaceAll]);
		result := StringReplace(result, '<', '&lt;', [rfReplaceAll]);
	end;

initialization
	writeln(stderr, 'initialization Utils');
	flush(stderr);
	InitCriticalSection(getGuidLock);
	randomize;
	if not DirectoryExists(writeDir) then
	begin
		writeln('can''t find directory ', writeDir);
		halt(1);
	end;
	if fpAccess(writeDir, W_OK) <> 0 then
	begin
		writeln('can''t write to directory ', writeDir);
		halt(1);
	end;
	layout := readFile(templatesDir + 'layout.html');

end.
