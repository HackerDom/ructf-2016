unit Filters;

{$mode objfpc}{$H+}

interface
	uses Sensor, fgl, SysUtils;

	type
		TValues = specialize TFPGList<single>;

		TRawListener = class abstract(TObject)
			protected
				sensor: TRawSensor;
				lastUpdate: int64;
				startTime: int64;
				values: TValues;
				rwSync: TSimpleRWSync;
			public
				constructor Create(const rawsensor: TRawSensor; const start: int64);
				function GetValues(const start, finish: int64): TValues;
				function HandleSecond(const rawValues: TRawValues): single; virtual; abstract;
		end;

		TRawCount = class(TRawListener)
			public
				function HandleSecond(const rawValues: TRawValues): single; override;
		end;

implementation	

	constructor TRawListener.Create(const rawsensor: TRawSensor; const start: int64);
	begin
		sensor := rawsensor;
		lastUpdate := start;
		startTime := start;
		values := TValues.Create;
		rwSync := TSimpleRWSync.Create;
	end;

	function TRawListener.GetValues(const start, finish: int64): TValues;
	var
		data, curData: TRawValues;
		i: longint;
		timestamp, curSecond: int64;
	begin
		if lastUpdate < finish then
		begin
			rwSync.beginWrite;
			if lastUpdate < finish then
			begin
				for i := lastUpdate to finish do
					values.add(0);
			
				data := sensor.GetValues(1000 * lastUpdate, 1000 * finish);
				curSecond := -1;
				curData := TRawValues.Create;
				for i := 0 to data.count - 1 do
				begin
					timestamp := data[i].timestamp div 1000;
					if (timestamp <> curSecond) and (curSecond <> -1) then
					begin
						values[timestamp - startTime] := HandleSecond(curData);
						curData.Clear;
					end;
					curData.Add(data[i]);
					curSecond := timestamp;
				end;
				curData.Free;
			
				lastUpdate := finish;

				data.Free;
			end;
			rwSync.EndWrite;
		end;

		result := TValues.Create;
		rwSync.BeginRead;
		for i := start to finish do
			result.add(values[i]);
		rwSync.EndWrite;
	end;

	function TRawCount.HandleSecond(const rawValues: TRawValues): single;
	begin
		result := rawValues.Count;
	end;
end.
