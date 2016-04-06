unit Sensor;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords} 

interface
	uses fgl;

	type
		TRawValue = record
			timestamp: int64;
			value: single;
			class operator= (const a, b: TRawValue): Boolean;
		end;
		TRawValues = specialize TFPGList<TRawValue>;
		TRawFilter = class abstract(TObject)
			public
				function GetValues(const start, finish: int64): TRawValues; virtual; abstract;
		end;
				
		TRawSensor = class abstract(TRawFilter)
			public
				constructor Create; virtual; abstract;
				procedure Run; virtual; abstract;
		end;

		TValues = specialize TFPGList<single>;
		TRawListener = class abstract(TObject)
			public
				constructor Create(const rawsensor: TRawFilter; const startTime: int64); virtual; abstract;
				function GetValues(const start, finish: int64): TValues; virtual; abstract;
		end;

		TRawCount = class(TRawListener)
			private
				filter: TRawFilter;
				lastUpdate: int64;
				results: TValues;
			public
				constructor Create(const rawfilter: TRawFilter; const startTime: int64); override;
				function GetValues(const start, finish: int64): TValues; override;
		end;

implementation

	class operator TRawValue.= (const a, b: TRawValue): Boolean;
	begin
		result := (a.timestamp = b.timestamp) and (a.value = b.value);
	end;

	constructor TRawCount.Create(const rawfilter: TRawFilter; const startTime: int64);
	begin
		filter := rawfilter;
		lastUpdate := startTime;
		results := TValues.Create;
	end;

	function TRawCount.GetValues(const start, finish: int64): TValues;
	var
		data: TRawValues;
		i: longint;
		timestamp: int64;
	begin
		if lastUpdate < finish then
		begin
			for i := lastUpdate to finish do
				results.add(0);
			
			data := filter.GetValues(1000 * lastUpdate, 1000 * finish);
			for i := 0 to data.count - 1 do
			begin
				timestamp := data[i].timestamp div 1000;
				results[timestamp] := results[timestamp] + 1;
			end;
			
			lastUpdate := finish;
		end;

		result := TValues.Create;
		for i := start to finish do
			result.add(results[i]);
	end;

end.
