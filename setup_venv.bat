@echo off
rem --------------------------------------------------
rem  Script: setup_venv.bat
rem  Descrição: Cria/ativa venv e abre terminal com debug
rem --------------------------------------------------

cd /d %~dp0
setlocal enabledelayedexpansion

:: === Configuração ===
set "VENV_DIR=venv"

:: === 1) Verifica se o venv existe ===
if exist "%VENV_DIR%\Scripts\activate.bat" (
    echo Ambiente virtual "%VENV_DIR%" já existe, seu arrombado.
) else (
    echo Ambiente virtual não encontrado.
    set /p "CREATE_VENV=Quer criar o ambiente virtual (s/n)? "
    if /I "!CREATE_VENV!"=="s" (
        echo Criando ambiente virtual...
        python -m venv "%VENV_DIR%"
        if errorlevel 1 (
            echo Deu ruim pra criar o venv, porra!
            pause
            exit /b 1
        ) else (
            echo Venv criado com sucesso, porra!
        )
    ) else (
        echo Beleza, sem venv então.
    )
)

:: === 2) Pergunta se quer ativar ===
set /p "ACTIVATE_VENV=Quer ativar o ambiente virtual agora (s/n)? "
if /I "!ACTIVATE_VENV!"=="s" (
    echo Abrindo novo terminal com o venv ativo...
    start "Venv Activated" cmd /k "cd /d %~dp0 && call ^"%VENV_DIR%\Scripts\activate.bat^" && echo Ambiente ativado! Agora manda pip install nessa joça..."
) else (
    echo Ta bom, fica sem ativar essa porra.
)

:: === 3) Debugging ===
echo.
echo ========== DEBUG INFO ==========
echo [DEBUG] Local do venv.........: %~dp0%VENV_DIR%
echo [DEBUG] Errorlevel final.....: %errorlevel%
echo [DEBUG] PATH atual...........:
echo %PATH%
echo =================================
echo.

pause
