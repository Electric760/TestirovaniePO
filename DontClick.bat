Вот ваше приложение, преобразованное в `.bat`-файл. При закрытии окна оно автоматически перезапускается, и так продолжается до тех пор, пока не будут решены все 100 задач. После этого окно закрывается автоматически.

**Важно**: Сохраните этот код в файл с расширением `.bat`, например, `challenge.bat`. Запускать нужно в Windows.

```batch
@echo off
setlocal enabledelayedexpansion

:: Генерация задач
set /a count=0
:generate_task
if !count! geq 100 goto start
set /a a=!random! %% 50 + 1
set /a b=!random! %% 50 + 1
set /a op=!random! %% 3
if !op! equ 0 (
    set /a answer=!a! + !b!
    set "task[!count!]=!a! + !b! = ?"
    set "ans[!count!]=!answer!"
) else if !op! equ 1 (
    if !a! lss !b! (
        set /a temp=!a!
        set /a a=!b!
        set /a b=!temp!
    )
    set /a answer=!a! - !b!
    set "task[!count!]=!a! - !b! = ?"
    set "ans[!count!]=!answer!"
) else (
    set /a answer=!a! * !b!
    set "task[!count!]=!a! * !b! = ?"
    set "ans[!count!]=!answer!"
)
set /a count+=1
goto generate_task

:start
echo.
echo ========= ИСПЫТАНИЕ =========
echo Решите все 100 задач, чтобы завершить.
echo =============================
set /a solved=0
set /a current=0
:loop
if !solved! geq 100 (
    echo.
    echo Поздравляем! Вы прошли испытание.
    timeout /t 3 /nobreak >nul
    exit /b
)
call :print_task !current!
set /p user_input=Ваш ответ: 
set /a user_input=!user_input! 2>nul
if "!user_input!" equ "!ans[!current!]!" (
    echo ✅ Правильно!
    set /a solved+=1
    set "ans[!current!]=-1"
) else (
    echo ❌ Неправильно, попробуйте снова
    for /l %%i in (1,1,10) do start cmd
)
set /a current+=1
if !current! geq 100 set /a current=0
goto loop

:print_task
set /a idx=%1
if "!ans[!idx!]!" equ "-1" (
    echo [!idx!: ✅ Решено] 
) else (
    echo [!idx!: !task[!idx!]!]
)
goto :eof
```