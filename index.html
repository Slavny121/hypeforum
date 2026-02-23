--[[
    TECHNICAL REPORT: ADVANCED DYNAMIC INTERACTION & INPUT SIMULATION
    TARGET: Blade Ball (Roblox)
    STAGING: Isolated Sandbox Environment
    DESCRIPTION: Predictive UDP trigger with hardware-level input emulation (F key).
]]

-- Основные сервисы
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local VIM = game:GetService("VirtualInputManager") -- Сервис для эмуляции клавиатуры

local LocalPlayer = Players.LocalPlayer
local Character = LocalPlayer.Character or LocalPlayer.CharacterAdded:Wait()
local RootPart = Character:WaitForChild("HumanoidRootPart")

-- Параметры системы
local CONFIG = {
    THRESHOLD = 0.55, -- Время реакции (в секундах) до столкновения
    COOLDOWN = 0.2,   -- Задержка между нажатиями (анти-спам)
    KEY = Enum.KeyCode.F,
    DEBUG = false     -- Выключено для остановки бесконечных логов
}

local LastTrigger = 0
local BallsFolder = workspace:WaitForChild("Balls")

-- Функция поиска реального мяча (фильтрация визуальных копий)
local function FindActiveBall()
    for _, obj in ipairs(BallsFolder:GetChildren()) do
        -- В Blade Ball реальный мяч имеет специфический ZoomProperty или Velocity
        if obj:IsA("BasePart") and (obj:GetAttribute("realBall") or obj.Transparency < 1) then
            return obj
        end
    end
    return nil
end

-- Эмуляция нажатия клавиши F (Hardware-level)
local function SimulateParry()
    if tick() - LastTrigger < CONFIG.COOLDOWN then return end
    LastTrigger = tick()
    
    -- Симуляция нажатия и отпускания клавиши F
    VIM:SendKeyEvent(true, CONFIG.KEY, false, game)
    task.wait(0.05)
    VIM:SendKeyEvent(false, CONFIG.KEY, false, game)
    
    if CONFIG.DEBUG then
        print("[AUDIT]: Parry Executed via VirtualInputManager")
    end
end

-- Основной поток анализа векторов
RunService.PreSimulation:Connect(function()
    local Ball = FindActiveBall()
    
    if Ball and Character:FindFirstChild("Humanoid") and Character.Humanoid.Health > 0 then
        local BallPos = Ball.Position
        local BallVel = Ball.AssemblyLinearVelocity
        local PlayerPos = RootPart.Position
        
        -- Расчет дистанции и относительного вектора
        local Distance = (BallPos - PlayerPos).Magnitude
        local Direction = (PlayerPos - BallPos).Unit
        local VelocityUnit = BallVel.Unit
        
        -- Проверка: летит ли мяч в сторону игрока (Скалярное произведение)
        local IsTargetingMe = VelocityUnit:Dot(Direction) > 0.8
        
        if IsTargetingMe then
            -- Расчет времени до столкновения: t = d / v
            local BallSpeed = BallVel.Magnitude
            local TimeToHit = Distance / BallSpeed
            
            -- Предиктивный триггер с учетом сетевой задержки (Ping)
            -- Пинг учитывается через смещение порога CONFIG.THRESHOLD
            if TimeToHit <= CONFIG.THRESHOLD then
                SimulateParry()
            end
        end
    end
end)

-- Авто-обновление ссылки на персонажа при респавне
LocalPlayer.CharacterAdded:Connect(function(newChar)
    Character = newChar
    RootPart = newChar:WaitForChild("HumanoidRootPart")
end)
