unit Crypto;

{$mode objfpc}{$H+}

interface

	function appendBlock(const prefix: string; const p: pointer): string;
	function encodeBlock(const p: pointer): string;

	function decode(const txt: string; var len: longint): pointer;

implementation

	const
		p: dword = $B7E15163;
		q: dword = $9E3779B9;
		r = 255;
		rr = 2 * (r + 1);
		key = 'Very secret key! Don''t say anybody!!';
		c = length(key) div 4;

	var
		s: array [0 .. rr - 1] of dword;

	function xorBlock(const a, b: pointer): string;
	var
		i: longint;
		p1, p2: pchar;
	begin
		setLength(result, 8);
		p1 := pchar(a);
		p2 := pchar(b);
		for i := 1 to 8 do
			result[i] := char(ord(p1[i]) xor ord(p2[i]));
	end;

	function appendBlock(const prefix: string; const p: pointer): string;
	var
		tmp, tmp2: string;
		i: longint;
	begin
		setlength(tmp, 8);
		for i := 1 to 8 do
			tmp[i] := pchar(p)[i - 1];
		tmp2 := copy(prefix, length(prefix) - 7, 8);
		tmp := xorBlock(@tmp[1], @tmp2[1]);
		result := prefix + encodeBlock(pointer(@tmp[1]));
	end;

	function rol(a, sh: dword): dword;
	begin
		sh := sh mod 32;
		result := (a shl sh) or (a shr (32 - sh));
	end;

	function encodeBlock(const p: pointer): string;
	var
		a, b, i: dword;
		res: pchar;
		tmp: array [0 .. 1] of dword; 
	begin
		a := pdword(p)[0];
		b := pdword(p)[1];

		a := a + s[0];
		b := b + s[1];

		for i := 1 to r do
		begin
			a := rol(a xor b, b) + s[2 * i];
			b := rol(b xor a, a) + s[2 * i + 1];
		end;

		tmp[0] := a;
		tmp[1] := b;
		res := pchar(@tmp[0]);
		setlength(result, 8);

		for i := 1 to 8 do
			result[i] := res[i];
	end;

	function ror(a, sh: dword): dword;
	begin
		sh := sh mod 32;
		result := (a shr sh) or (a shl (32 - sh)); // TODO check!!!
	end;

	procedure decodeBlock(const txt: string; var a, b: dword);
	var
		i: longint;
	begin
		a := pdword(@txt)[0];
		b := pdword(@txt)[1];

		for i := r downto 1 do
		begin
			b := ror(b - s[2 * i + 1], a) xor a;
			a := ror(a - s[2 * i], b) xor b;
		end;

		b := b - s[1];
		a := a - s[0];
	end;

	function decode(const txt: string; var len: longint): pointer;
	var
		res: pdword;
		tmp: string;
		i, n: longint;
	begin
		n := length(txt) div 4;
		getmem(res, n);
		
		decodeBlock(txt, res[0], res[1]);
		for i := 1 to n - 1 do
		begin
			tmp := copy(txt, 8 * i + 1, 8);
			decodeBlock(tmp, res[2 * i], res[2 * i + 1]);
			tmp := copy(txt, 8 * i - 7, 8);
			tmp := xorBlock(@tmp, @res[2 * i]);
			res[2 * i] := pdword(@tmp[1])[0];
			res[2 * i + 1] := pdword(@tmp[1])[1];
		end;
		result := pointer(@res[0]);
		len := length(txt);
	end;

	function max(const a, b: dword): dword;
	begin
		if a < b then
			result := b
		else
			result := a;
	end;

	procedure expansionKey;
	var
		l: array [0 .. c - 1] of dword;
		pp: pdword;
		i, j, g, h, k: dword;
	begin
		pp := pdword(@key[1]);
		for i := 0 to c - 1 do
			l[i] := pp[i];

		s[0] := p;
		for i := 1 to rr - 1 do
			s[i] := s[i - 1] + q;
	
		g := 0;
		h := 0;
		i := 0;
		j := 0;

		for k := 1 to max(3 * c, 3 * rr) do
		begin
			g := rol(s[i] + g + h, 3);
			s[i] := g;
			h := rol(l[j] + g + h, g + h);
			l[j] := h;
			i := (i + 1) mod rr;
			j := (j + 1) mod c;
		end;
	end;

initialization
	expansionKey;
end.
