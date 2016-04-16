program meters;

{$mode objfpc}{$H+}

uses
	cthreads, fphttpapp, fpWebFile, UserController, AccountController, DashboardController, RawSensor, DashboardContainer, RootController, RC5;

function StartTickSensor(p: pointer): int64;
begin
	RawTickSensor.Run;
	result := 0;
end;

function StartRandomSensor(p: pointer): int64;
begin
	RawRandomSensor.Run;
	result := 0;
end;

procedure StartSensors;
begin
	BeginThread(@StartTickSensor);
	BeginThread(@StartRandomSensor);
end;


begin
	Application.Title := 'meters';
	Application.Port := 6725;
	Application.Threaded := True;
	Application.QueueSize := 100;
	Application.Initialize;

	AccountManager.Initialize;
	DashboardManager.Initialize;

	RawTickSensor.Initialize;
	RawRandomSensor.Initialize;

	StartSensors;

	LoadKey;

	RegisterFileLocation('js', 'js');
	RegisterFileLocation('css', 'css');
	MimeTypesFile := '/etc/mime.types';

	writeln(stderr, 'end of initialization');
	flush(stderr);

	Application.Run;
end.
