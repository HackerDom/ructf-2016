program meters;

{$mode objfpc}{$H+}

uses
	cthreads, fphttpapp, fpWebFile, UserController, AccountController, DashboardController, Sensor, DashboardContainer, RootController;


{
procedure StartSensors;
begin
	RawTickSensor.Initialize;
	BeginThread(@RawTickSensor.Run);
end;
}

begin
	Application.Title := 'meters';
	Application.Port := 6725;
	Application.Threaded := True;
	Application.QueueSize := 100;
	Application.Initialize;

	AccountManager.Initialize;
	DashboardManager.Initialize;

//	StartSensors;

	RegisterFileLocation('js', 'js');
	RegisterFileLocation('css', 'css');
	MimeTypesFile := '/etc/mime.types';

	writeln(stderr, 'end of initialization');
	flush(stderr);

	Application.Run;
end.
