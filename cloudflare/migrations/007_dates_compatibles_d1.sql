DROP TRIGGER IF EXISTS valider_dates_scrutin_insert;
DROP TRIGGER IF EXISTS valider_dates_scrutin_update;
CREATE TRIGGER valider_dates_scrutin_insert BEFORE INSERT ON scrutins
WHEN NEW.debut_utc IS NULL OR NEW.fin_utc IS NULL
 OR length(NEW.debut_utc)<>20 OR length(NEW.fin_utc)<>20
 OR strftime('%Y-%m-%dT%H:%M:%SZ',NEW.debut_utc,'+0 seconds') IS NOT NEW.debut_utc
 OR strftime('%Y-%m-%dT%H:%M:%SZ',NEW.fin_utc,'+0 seconds') IS NOT NEW.fin_utc
 OR unixepoch(NEW.fin_utc)<=unixepoch(NEW.debut_utc)
BEGIN SELECT RAISE(ABORT,'invalid poll schedule'); END;
CREATE TRIGGER valider_dates_scrutin_update BEFORE UPDATE OF debut_utc,fin_utc ON scrutins
WHEN NEW.debut_utc IS NULL OR NEW.fin_utc IS NULL
 OR length(NEW.debut_utc)<>20 OR length(NEW.fin_utc)<>20
 OR strftime('%Y-%m-%dT%H:%M:%SZ',NEW.debut_utc,'+0 seconds') IS NOT NEW.debut_utc
 OR strftime('%Y-%m-%dT%H:%M:%SZ',NEW.fin_utc,'+0 seconds') IS NOT NEW.fin_utc
 OR unixepoch(NEW.fin_utc)<=unixepoch(NEW.debut_utc)
BEGIN SELECT RAISE(ABORT,'invalid poll schedule'); END;
