unit RawSensor;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords} 

interface
	uses
		cthreads, fgl, SysUtils, Classes, Utils;

	type
		TRawValue = record
			timestamp: longint;
			value: double;
			class operator= (const a, b: TRawValue): Boolean;
		end;
		TRawValues = specialize TFPGList<TRawValue>;

		TRawSensor = class abstract(TObject)
			protected
				values: TRawValues;
				rwSync: TSimpleRWSync;
				ready: int64;
			public
				procedure Initialize;
				function GetValues(const start, finish: int64): TRawValues;
		end;

		TRawTick = class(TRawSensor)
			public
				procedure Run;
		end;

		TRawRandom = class(TRawSensor)
			public
				procedure Run;
		end;

	var
		RawTickSensor: TRawTick;
		RawRandomSensor: TRawRandom;

implementation

	class operator TRawValue.= (const a, b: TRawValue): Boolean;
	begin
		result := (a.timestamp = b.timestamp) and (a.value = b.value);
	end;

	procedure TRawSensor.Initialize;
	begin
		values := TRawValues.Create;
		rwSync := TSimpleRWSync.Create;
		ready := -1;
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

			rwSync.BeginWrite;
			values.Add(tmp);
			if ready < tmp.timestamp then
				ready := tmp.timestamp;
			rwSync.EndWrite;

			sleep(100);
		end;
	end;

	procedure TRawRandom.Run;
	var
		tmp: TRawValue;
	begin
		while true do
		begin
			tmp.value := (GetGuid mod 65536) / 65536;
			tmp.timestamp := tsnow;

			rwSync.BeginWrite;
			values.Add(tmp);
			if ready < tmp.timestamp then
				ready := tmp.timestamp;
			rwSync.EndWrite;

			sleep(trunc(GetGuid mod 65536 / 655.36));
		end;
	end;

initialization
	writeln(stderr, 'initialization Sensor');
	flush(stderr);
	RawTickSensor := TRawTick.Create;
	RawRandomSensor := TRawRandom.Create;

end.
