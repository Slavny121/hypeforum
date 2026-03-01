--[[
    AUDIT ULTRA v21: THE FINAL RECKONING
    - Fixed TeamCheck (Enemies Only)
    - Persistent Chams (Auto-reapply on Respawn)
    - Viewmodel (Weapon) Chams
    - Hardcoded Index Hook for Recoil/Spread/Wallbang
    - Round Start Bypass (Move & Shoot during freeze)
    - Improved Glass UI with Smooth Tweens & Particle Fragments
]]

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService")
local CoreGui = game:GetService("CoreGui")
local TweenService = game:GetService("TweenService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local LocalPlayer = Players.LocalPlayer
local Camera = workspace.CurrentCamera

-- [[ НАСТРОЙКИ ]]
local Settings = {
    Aimbot = { Enabled = false, Key = Enum.KeyCode.LeftAlt, Fov = 150, Smoothness = 3, TargetPart = "Head", ShowFov = true },
    Visuals = { Enabled = false, TeamCheck = true, Names = true, Boxes = true, Chams = true, ViewmodelChams = true, Color = Color3.fromRGB(0, 255, 255) },
    Rage = { SilentAim = false, Wallbang = false, NoRecoil = false, NoSpread = false, RapidFire = false, AutoShoot = false, FreezeBypass = false },
    Misc = { Bhop = false, Speed = 16 },
    UI = { Accent = Color3.fromRGB(0, 180, 255) }
}

-- [[ УДАЛЕНИЕ СТАРОГО ]]
for _, old in pairs(CoreGui:GetChildren()) do if old.Name == "AuditUltra" then old:Destroy() end end

-- [[ ГЕНЕРАЦИЯ UI ]]
local ScreenGui = Instance.new("ScreenGui", CoreGui); ScreenGui.Name = "AuditUltra"

local MainFrame = Instance.new("Frame", ScreenGui)
MainFrame.Size = UDim2.new(0, 650, 0, 480); MainFrame.Position = UDim2.new(0.5, -325, 0.5, -240)
MainFrame.BackgroundColor3 = Color3.fromRGB(10, 10, 15); MainFrame.BackgroundTransparency = 0.15; MainFrame.BorderSizePixel = 0
Instance.new("UICorner", MainFrame).CornerRadius = UDim.new(0, 15)

-- Эффект свечения краев
local UIStroke = Instance.new("UIStroke", MainFrame)
UIStroke.Thickness = 1.5; UIStroke.Color = Settings.UI.Accent; UIStroke.Transparency = 0.5

-- Контейнер частиц (Осколки)
local ParticleCanvas = Instance.new("Frame", MainFrame)
ParticleCanvas.Size = UDim2.new(1, 0, 1, 0); ParticleCanvas.BackgroundTransparency = 1; ParticleCanvas.ClipsDescendants = true

local function SpawnShard(x, y)
    local shard = Instance.new("Frame", ParticleCanvas)
    shard.Size = UDim2.new(0, math.random(2,5), 0, math.random(2,5))
    shard.Position = UDim2.new(0, x or math.random(0, 650), 0, y or math.random(0, 480))
    shard.BackgroundColor3 = Settings.UI.Accent; shard.BackgroundTransparency = 0.3; shard.Rotation = math.random(0, 360)
    Instance.new("UICorner", shard).CornerRadius = UDim.new(1, 0)
    
    local target = UDim2.new(shard.Position.X.Scale, shard.Position.X.Offset + math.random(-50, 50), shard.Position.Y.Scale, shard.Position.Y.Offset + math.random(-50, 50))
    TweenService:Create(shard, TweenInfo.new(1.5, Enum.EasingStyle.Quart, Enum.EasingDirection.Out), {Position = target, BackgroundTransparency = 1, Rotation = shard.Rotation + 180}):Play()
    task.delay(1.5, function() shard:Destroy() end)
end

-- Эффект при движении мыши в меню
MainFrame.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement then
        if math.random(1, 5) == 1 then SpawnShard(input.Position.X - MainFrame.AbsolutePosition.X, input.Position.Y - MainFrame.AbsolutePosition.Y) end
    end
end)

-- Навигация и Контент
local Sidebar = Instance.new("Frame", MainFrame)
Sidebar.Size = UDim2.new(0, 160, 1, 0); Sidebar.BackgroundTransparency = 0.95; Sidebar.BackgroundColor3 = Color3.new(0,0,0)

local Content = Instance.new("Frame", MainFrame)
Content.Position = UDim2.new(0, 170, 0, 10); Content.Size = UDim2.new(1, -180, 1, -20); Content.BackgroundTransparency = 1

local Pages = {}
local function CreatePage(name)
    local p = Instance.new("ScrollingFrame", Content)
    p.Size = UDim2.new(1, 0, 1, 0); p.BackgroundTransparency = 1; p.Visible = false; p.ScrollBarThickness = 2
    p.CanvasSize = UDim2.new(0,0,0,0); p.AutomaticCanvasSize = Enum.AutomaticSize.Y
    local layout = Instance.new("UIListLayout", p); layout.Padding = UDim.new(0, 12); layout.SortOrder = Enum.SortOrder.LayoutOrder
    Pages[name] = p
    return p
end

local function AddTab(name)
    local b = Instance.new("TextButton", Sidebar)
    b.Size = UDim2.new(1, -20, 0, 40); b.Position = UDim2.new(0, 10, 0, 20 + (#Sidebar:GetChildren()-1)*50)
    b.BackgroundColor3 = Color3.new(1,1,1); b.BackgroundTransparency = 0.98; b.Text = name; b.TextColor3 = Color3.new(0.6,0.6,0.6)
    b.Font = Enum.Font.GothamMedium; b.TextSize = 14; Instance.new("UICorner", b).CornerRadius = UDim.new(0, 8)
    
    b.MouseButton1Click:Connect(function()
        for k, v in pairs(Pages) do 
            if k == name then
                v.Visible = true; v.GroupTransparency = 1
                TweenService:Create(v, TweenInfo.new(0.4), {GroupTransparency = 0}):Play()
                b.TextColor3 = Color3.new(1,1,1); b.BackgroundTransparency = 0.9
            else
                v.Visible = false; b.TextColor3 = Color3.new(0.6,0.6,0.6); b.BackgroundTransparency = 0.98
            end
        end
    end)
end

-- Вкладки
CreatePage("Аимбот"); AddTab("Аимбот")
CreatePage("Визуалы"); AddTab("Визуалы")
CreatePage("Рейдж"); AddTab("Рейдж")
CreatePage("Разное"); AddTab("Разное")
Pages["Аимбот"].Visible = true

-- Кастомные элементы управления (Крупные ползунки)
local function CreateToggle(parent, text, config, key)
    local b = Instance.new("TextButton", parent)
    b.Size = UDim2.new(1, -5, 0, 45); b.BackgroundColor3 = Color3.fromRGB(25, 25, 30); b.Text = "  " .. text
    b.TextColor3 = Color3.new(0.8, 0.8, 0.8); b.Font = Enum.Font.Gotham; b.TextSize = 14; b.TextXAlignment = Enum.TextXAlignment.Left
    local c = Instance.new("UICorner", b).CornerRadius = UDim.new(0, 10)
    
    local check = Instance.new("Frame", b)
    check.Size = UDim2.new(0, 20, 0, 20); check.Position = UDim2.new(1, -35, 0.5, -10)
    check.BackgroundColor3 = config[key] and Settings.UI.Accent or Color3.fromRGB(40, 40, 45)
    Instance.new("UICorner", check).CornerRadius = UDim.new(0, 6)

    b.MouseButton1Click:Connect(function()
        config[key] = not config[key]
        TweenService:Create(check, TweenInfo.new(0.3), {BackgroundColor3 = config[key] and Settings.UI.Accent or Color3.fromRGB(40, 40, 45)}):Play()
    end)
end

local function CreateSlider(parent, text, config, key, min, max)
    local container = Instance.new("Frame", parent)
    container.Size = UDim2.new(1, -5, 0, 70); container.BackgroundTransparency = 1
    
    local label = Instance.new("TextLabel", container)
    label.Size = UDim2.new(1, 0, 0, 20); label.Text = text .. ": " .. config[key]; label.TextColor3 = Color3.new(1,1,1)
    label.Font = Enum.Font.Gotham; label.TextSize = 13; label.BackgroundTransparency = 1; label.TextXAlignment = Enum.TextXAlignment.Left

    local slideBack = Instance.new("TextButton", container)
    slideBack.Size = UDim2.new(1, 0, 0, 12); slideBack.Position = UDim2.new(0, 0, 0, 35); slideBack.BackgroundColor3 = Color3.fromRGB(30, 30, 35); slideBack.Text = ""
    Instance.new("UICorner", slideBack).CornerRadius = UDim.new(1, 0)
    
    local fill = Instance.new("Frame", slideBack)
    fill.Size = UDim2.new((config[key]-min)/(max-min), 0, 1, 0); fill.BackgroundColor3 = Settings.UI.Accent
    Instance.new("UICorner", fill).CornerRadius = UDim.new(1, 0)

    local dragging = false
    local function update(input)
        local per = math.clamp((input.Position.X - slideBack.AbsolutePosition.X) / slideBack.AbsoluteSize.X, 0, 1)
        local val = math.floor(min + (max - min) * per)
        config[key] = val; label.Text = text .. ": " .. val; fill.Size = UDim2.new(per, 0, 1, 0)
    end
    slideBack.InputBegan:Connect(function(i) if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = true; update(i) end end)
    UserInputService.InputEnded:Connect(function(i) if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end end)
    UserInputService.InputChanged:Connect(function(i) if dragging and i.UserInputType == Enum.UserInputType.MouseMovement then update(i) end end)
end

-- Заполнение настроек
CreateToggle(Pages["Аимбот"], "Включить Аим", Settings.Aimbot, "Enabled")
CreateSlider(Pages["Аимбот"], "Радиус захвата", Settings.Aimbot, "Fov", 50, 800)
CreateSlider(Pages["Аимбот"], "Плавность", Settings.Aimbot, "Smoothness", 1, 20)

CreateToggle(Pages["Визуалы"], "Включить ESP", Settings.Visuals, "Enabled")
CreateToggle(Pages["Визуалы"], "Подсветка (Chams)", Settings.Visuals, "Chams")
CreateToggle(Pages["Визуалы"], "Подсветка Оружия", Settings.Visuals, "ViewmodelChams")
CreateToggle(Pages["Визуалы"], "Имена и Боксы", Settings.Visuals, "Names")

CreateToggle(Pages["Рейдж"], "Silent Aim", Settings.Rage, "SilentAim")
CreateToggle(Pages["Рейдж"], "Wallbang (Сквозь стены)", Settings.Rage, "Wallbang")
CreateToggle(Pages["Рейдж"], "Без отдачи и разброса", Settings.Rage, "NoRecoil") -- Объединено для надежности
CreateToggle(Pages["Рейдж"], "Быстрая стрельба", Settings.Rage, "RapidFire")
CreateToggle(Pages["Рейдж"], "Авто-выстрел", Settings.Rage, "AutoShoot")
CreateToggle(Pages["Рейдж"], "Bypass Freeze (Двигаться в начале)", Settings.Rage, "FreezeBypass")

CreateToggle(Pages["Разное"], "Bhop", Settings.Misc, "Bhop")
CreateSlider(Pages["Разное"], "Скорость бега", Settings.Misc, "Speed", 16, 100)

-- [[ ЛОГИКА ЧИТА ]]

-- Фикс Чамсов и ESP (Только враги + Респавн)
local function ApplyChams(player)
    if player == LocalPlayer then return end
    player.CharacterAdded:Connect(function(char)
        if Settings.Visuals.TeamCheck and player.Team == LocalPlayer.Team then return end
        task.wait(0.5)
        if Settings.Visuals.Chams and Settings.Visuals.Enabled then
            local h = Instance.new("Highlight", char)
            h.Name = "AuditHighlight"; h.FillColor = Settings.UI.Accent; h.OutlineTransparency = 1; h.FillTransparency = 0.4
            h.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
        end
    end)
end
Players.PlayerAdded:Connect(ApplyChams)
for _, p in pairs(Players:GetPlayers()) do ApplyChams(p) end

-- Умный Хук на Оружие (Recoil / Wallbang)
local mt = getrawmetatable(game)
local old_index = mt.__index
setreadonly(mt, false)

mt.__index = newcclosure(function(t, k)
    if not checkcaller() then
        if k == "Recoil" or k == "VisualRecoil" or k == "Spread" or k == "Inaccuracy" then
            if Settings.Rage.NoRecoil then return 0 end
        end
        if k == "Penetration" or k == "Range" then
            if Settings.Rage.Wallbang then return 9999 end
        end
        if k == "FireRate" and Settings.Rage.RapidFire then
            return 0.02
        end
    end
    return old_index(t, k)
end)
setreadonly(mt, true)

-- Bypass Freeze (Начало раунда)
RunService.Stepped:Connect(function()
    if Settings.Rage.FreezeBypass then
        local gui = LocalPlayer.PlayerGui:FindFirstChild("MainGui")
        if gui and gui:FindFirstChild("FreezeFrame") then
            gui.FreezeFrame.Visible = false -- Убираем визуал заморозки
        end
        -- В CB заморозка обычно работает через WalkSpeed = 0 в начале
        local char = LocalPlayer.Character
        if char and char:FindFirstChild("Humanoid") and char.Humanoid.WalkSpeed < 1 then
            char.Humanoid.WalkSpeed = Settings.Misc.Speed
        end
    end
end)

-- Основной цикл (Aimbot / ESP / AutoShoot)
local FOVCircle = Drawing.new("Circle")
FOVCircle.Thickness = 1; FOVCircle.NumSides = 64; FOVCircle.Color = Settings.UI.Accent

RunService.RenderStepped:Connect(function()
    local MousePos = UserInputService:GetMouseLocation()
    FOVCircle.Visible = Settings.Aimbot.ShowFov and Settings.Aimbot.Enabled
    FOVCircle.Position = MousePos
    FOVCircle.Radius = Settings.Aimbot.Fov

    -- Viewmodel Chams (Оружие в руках)
    if Settings.Visuals.ViewmodelChams and Camera:FindFirstChild("Viewmodel") then
        for _, part in pairs(Camera.Viewmodel:GetDescendants()) do
            if part:IsA("BasePart") then
                part.Color = Settings.UI.Accent; part.Material = Enum.Material.Glass
            end
        end
    end

    local Target = nil
    local MinDist = Settings.Aimbot.Fov

    for _, p in pairs(Players:GetPlayers()) do
        if p == LocalPlayer or (Settings.Visuals.TeamCheck and p.Team == LocalPlayer.Team) then continue end
        local char = p.Character
        if char and char:FindFirstChild("Head") and char:FindFirstChild("Humanoid") and char.Humanoid.Health > 0 then
            local head = char.Head
            local screenPos, onScreen = Camera:WorldToViewportPoint(head.Position)
            
            if onScreen then
                local dist = (Vector2.new(screenPos.X, screenPos.Y) - MousePos).Magnitude
                if dist < MinDist then
                    MinDist = dist; Target = head
                end
            end
        end
    end

    -- Наводка и Автовыстрел
    if Target then
        if UserInputService:IsKeyDown(Settings.Aimbot.Key) or Settings.Rage.SilentAim then
            local targetPos = Camera:WorldToViewportPoint(Target.Position)
            if Settings.Rage.SilentAim then
                 -- Имитация идеальной точности при клике
                 if UserInputService:IsMouseButtonPressed(Enum.UserInputType.MouseButton1) then
                    Camera.CFrame = CFrame.new(Camera.CFrame.Position, Target.Position)
                 end
            else
                Camera.CFrame = Camera.CFrame:Lerp(CFrame.new(Camera.CFrame.Position, Target.Position), Settings.Aimbot.Smoothness/100)
            end
        end
        
        -- AutoShoot (Стреляет если прицел на враге)
        if Settings.Rage.AutoShoot then
            local mouseTarget = LocalPlayer:GetMouse().Target
            if mouseTarget and mouseTarget:IsDescendantOf(Target.Parent) then
                mouse1press(); task.wait(); mouse1release()
            end
        end
    end
end)

-- Misc (Speed & Bhop)
RunService.Heartbeat:Connect(function()
    local char = LocalPlayer.Character
    if char and char:FindFirstChild("Humanoid") then
        char.Humanoid.WalkSpeed = Settings.Misc.Speed
        if Settings.Misc.Bhop and UserInputService:IsKeyDown(Enum.KeyCode.Space) then
            char.Humanoid.Jump = true
        end
    end
end)

-- Открытие меню на INSERT
UserInputService.InputBegan:Connect(function(i)
    if i.KeyCode == Enum.KeyCode.Insert then 
        MainFrame.Visible = not MainFrame.Visible
        UserInputService.MouseIconEnabled = MainFrame.Visible
    end
end)
