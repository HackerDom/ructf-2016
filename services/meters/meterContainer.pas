unit meterContainer;

interface
	const
		METERS_COUNT = 128;
		HISTORY_SIZE = 1024;

	type
		TMeter = record
			value: qword;
			timestamp: longword;
			h: longword;
		end;
		PTMeter = ^TMeter;
		TMeterContainer = record
			states: array [0 .. HISTORY_SIZE - 1] of PTMeter;
			current: PTMeter;
			index: longint;
		end;
		TMeterResults = array [1 .. METERS_COUNT] of TMeter;
		TMetersHistory = array [1 .. METERS_COUNT] of array of TMeter;

	procedure AddMeterState(const meter: longint; const state: PTMeter);
	function GetAllResults(): TMeterResults;
	function GetAllHistory(): TMetersHistory;

implementation
	uses
		cthreads, log, SysUtils;

	var
		locks: array [1 .. METERS_COUNT] of TRTLCriticalSection;
		meters: array [1 .. METERS_COUNT] of TMeterContainer;

	procedure AddMeterState(const meter: longint; const state: PTMeter);
	var
		ind: longint;
	begin
		info(format('get info from %d: value: %u, timestamp %u, h: %u', [meter, state^.value, state^.timestamp, state^.h]));

		EnterCriticalSection(locks[meter]);
		
		ind := meters[meter].index;
		ind := (ind + 1) mod HISTORY_SIZE;
		if meters[meter].states[ind] <> nil then
			Dispose(meters[meter].states[ind]);
		meters[meter].states[ind] := state;
		meters[meter].index := ind;
		meters[meter].current := state;

		LeaveCriticalSection(locks[meter]);
	end;

	function GetAllResults(): TMeterResults;
	var
		i: longint;
	begin
		for i := 1 to METERS_COUNT do
		begin
			EnterCriticalSection(locks[i]);
			GetAllResults[i] := meters[i].current^;
			LeaveCriticalSection(locks[i]);
		end;
	end;

	function GetAllHistory(): TMetersHistory;
	var
		i, j, cnt: longint;
	begin
		for i := 1 to METERS_COUNT do
		begin
			EnterCriticalSection(locks[i]);
			cnt := 0;
			for j := 0 to HISTORY_SIZE - 1 do
				if meters[i].states[j] <> nil then
					inc(cnt);
			SetLength(GetAllHistory[i], cnt);
			for j := 0 to cnt - 1 do
				GetAllHistory[i][j] := meters[i].states[(meters[i].index + j) mod HISTORY_SIZE]^;
			LeaveCriticalSection(locks[i]);
		end;
	end;

	procedure InitLocks();
	var
		i: longint;
	begin
		for i := 1 to METERS_COUNT do
			InitCriticalSection(locks[i])
	end;

	procedure InitContainer();
	var
		i, j: longint;
	begin
		for i := 1 to METERS_COUNT do
		begin
			meters[i].index := HISTORY_SIZE - 1;
			meters[i].current := nil;
			for j := 0 to HISTORY_SIZE - 1 do
				meters[i].states[j] := nil;
		end;
	end;

	procedure DoneLocks();
	var
		i: longint;
	begin
		for i := 1 to METERS_COUNT do
			DoneCriticalSection(locks[i]);
	end;

initialization
	InitLocks();
	InitContainer();

finalization
	DoneLocks();

end.
