unit Sensor;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords} 

interface
	uses fgl, SysUtils, Classes;

	type
		TRawValue = record
			timestamp: int64;
			value: single;
			class operator= (const a, b: TRawValue): Boolean;
		end;
		TRawValues = specialize TFPGList<TRawValue>;

		TRawSensor = class abstract(TObject)
			protected
				values: TRawValues;
				log: Text;
				rwSync: TSimpleRWSync;
				logFileName: unicodestring;
				ready: int64;
			public
				constructor Create;
				procedure Run; virtual; abstract;
				function GetValues(const start, finish: int64): TRawValues;
		end;

		TRawTick = class(TRawSensor)
			public
				constructor Create;
				procedure Run; override;
		end;

implementation
	const
		logDir = './logs/';
		UnixStartDate: TDateTime = 25569.0;

	function DateTimeToUnix(dtDate: TDateTime): Longint;
	begin
		result := Round((dtDate - UnixStartDate) * int64(86400000));
	end;

	class operator TRawValue.= (const a, b: TRawValue): Boolean;
	begin
		result := (a.timestamp = b.timestamp) and (a.value = b.value);
	end;

	constructor TRawSensor.Create;
	var
		tmp: TRawValue;
		logFilePath: unicodestring;
	begin
		values := TRawValues.Create;
		logFilePath := logDir + logFileName;
		assign(log, logFileName);
		rwSync := TSimpleRWSync.Create;
		ready := -1;

		if not FileExists(logFileName) then
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
		close(log);
		append(log);
	end;

	function TRawSensor.GetValues(const start, finish: int64): TRawValues;
	var
		i, attempts: longint;
	begin
		attempts := 0;
		while (finish > ready) and (attempts < 100) do
		begin
			inc(attempts);
			TThread.Yield;
		end;

		result := TRawValues.Create;
		rwSync.BeginRead;
		for i := 0 to values.Count - 1 do
			if (start <= values[i].timestamp) and (values[i].timestamp < finish) then
				result.add(values[i]);
		rwSync.EndRead;
	end;

	constructor TRawTick.Create;
	begin
		logFileName := 'ticks.log';
		Inherited;
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
			tmp.value := current - prev;
			tmp.timestamp := DateTimeToUnix(current);
			writeln(log, tmp.timestamp, tmp.value);

			rwSync.BeginWrite;
			values.Add(tmp);
			if ready < tmp.timestamp then
				ready := tmp.timestamp;
			rwSync.EndWrite;

			sleep(100);
		end;
	end;
end.
