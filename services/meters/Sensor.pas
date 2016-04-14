unit Sensor;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords} 

interface
	uses
		cthreads, fgl, SysUtils, Classes, Utils;

	type
		TRawValue = record
			timestamp: longint;
			value: single;
			class operator= (const a, b: TRawValue): Boolean;
		end;
		TRawValues = specialize TFPGList<TRawValue>;

		TRawSensor = class abstract(TObject)
			protected
				values: TRawValues;
				log: Text;
				rwSync: TSimpleRWSync;
				ready: int64;
				procedure Initialize(const fileName: unicodestring);
			public
				function GetValues(const start, finish: int64): TRawValues;
		end;

		TRawTick = class(TRawSensor)
			public
				procedure Initialize;
				procedure Run;
		end;

	var
		RawTickSensor: TRawTick;

implementation
	const
		UnixStartDate: TDateTime = 25569.0;

	function DateTimeToUnix(dtDate: TDateTime): Longint;
	begin
		result := trunc((dtDate - UnixStartDate) * 86400);
	end;

	class operator TRawValue.= (const a, b: TRawValue): Boolean;
	begin
		result := (a.timestamp = b.timestamp) and (a.value = b.value);
	end;

	procedure TRawSensor.Initialize(const fileName: unicodestring);
	var
		tmp: TRawValue;
		logFilePath: unicodestring;
	begin
		values := TRawValues.Create;
		logFilePath := writeDir + fileName;
		assign(log, logFilePath);
		rwSync := TSimpleRWSync.Create;
		ready := -1;

		if not FileExists(logFilePath) then
		begin
			rewrite(log);
			exit;
		end;

		reset(log);
		
		while not seekeof(log) do
		begin
			read(log, tmp.timestamp, tmp.value);
			values.Add(tmp);
		end;
		append(log);
	end;

	function TRawSensor.GetValues(const start, finish: int64): TRawValues;
	var
		i, attempts: longint;
	begin
		attempts := 0;
		while (finish >= ready) and (attempts < 100) do
		begin
			inc(attempts);
			sleep(1);
		end;

		result := TRawValues.Create;
		rwSync.BeginRead;
		for i := 0 to values.Count - 1 do
			if (start <= values[i].timestamp) and (values[i].timestamp < finish) then
				result.add(values[i]);
		rwSync.EndRead;
	end;

	procedure TRawTick.Initialize;
	begin
		Inherited Initialize('ticks.log');
	end;

	procedure TRawTick.Run;
	var
		prev, current: TDateTime;
		tmp: TRawValue;
	begin
		prev := now;
		while true do
		begin
			current := now;
			tmp.value := (current - prev) * 1e6;
			tmp.timestamp := DateTimeToUnix(current);
			prev := current;
			writeln(log, tmp.timestamp, ' ', tmp.value:0:10);
			flush(log);

			rwSync.BeginWrite;
			values.Add(tmp);
			if ready < tmp.timestamp then
				ready := tmp.timestamp;
			rwSync.EndWrite;

			sleep(100);
		end;
	end;

initialization
	writeln(stderr, 'initialization Sensor');
	flush(stderr);
	RawTickSensor := TRawTick.Create;

end.
