program httpproject1;

{$mode objfpc}{$H+}

uses
	cthreads, fphttpapp, UserController, AccountController, DashboardController;

begin
	Application.Title := 'meters';
	Application.Port := 6725;
	Application.Threaded := True;
	Application.QueueSize := 100;
	Application.Initialize;
	AccountManager.Initialize;
	Application.Run;
end.
