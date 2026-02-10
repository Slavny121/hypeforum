const ITEMS = {
            "Scrap": { icon: "⚙", color: "#888", rarity: "Common", value: 15, desc: "Recyclable metal.", type: "trash" },
            "Crystal": { icon: "💎", color: "#0ff", rarity: "Common", value: 60, desc: "Focuses energy.", type: "trash" },
            "Dark Matter": { icon: "🌑", color: "#80f", rarity: "Rare", value: 250, desc: "Strange substance.", type: "trash" },
            "Cyber Chip": { icon: "💾", color: "#0f0", rarity: "Rare", value: 120, desc: "Legacy tech.", type: "trash" },
            "Ancient Tech": { icon: "🏺", color: "#f80", rarity: "Epic", value: 1000, desc: "Mysterious component.", type: "trash" },
            "Energy Sphere": { icon: "🔋", color: "#ff0", rarity: "Rare", value: 500, desc: "Instantly gives 5000 NRG.", type: "usable", effect: (s) => s.energy += 5000 },
            "Overdrive Core": { icon: "⚡", color: "#f0f", rarity: "Epic", value: 2000, desc: "Permanent +10% production.", type: "usable", effect: (s) => s.multiplier += 0.1 },
            "Basic Drone": { icon: "🚁", color: "#0ff", rarity: "Common", value: 150, desc: "Standard harvester.", type: "drone", droneType: "basic" },
            "Mega Drone": { icon: "🤖", color: "#f0f", rarity: "Legendary", value: 5000, desc: "Deploys a Mega Drone.", type: "drone", droneType: "mega" },
            "Fragile Drone": { icon: "🎯", color: "#f44", rarity: "Rare", value: 1000, desc: "High power, low HP.", type: "drone", droneType: "fragile" },
            "Tank Drone": { icon: "🛡️", color: "#44f", rarity: "Rare", value: 1500, desc: "High HP harvester.", type: "drone", droneType: "tank" },
            "VIP Drone": { icon: "👑", color: "#fd0", rarity: "Legendary", value: 1000000, desc: "God-tier drone.", type: "drone", droneType: "vip" },
            "Vip Crown": { icon: "💍", color: "#fd0", rarity: "Legendary", value: 10000, desc: "Grants VIP Status.", type: "usable", effect: (s) => s.isVIP = true }
        };

        // --- ACHIEVEMENTS DATABASE ---
        const ACHIEVEMENTS = [
            { id: "first_click", title: "Neural Spark", desc: "First energy harvest.", goal: 1, type: "click" },
            { id: "rich_10k", title: "Energy Baron", desc: "Accumulate 10,000 NRG.", goal: 10000, type: "energy" },
            { id: "drone_master", title: "Hive Mind", desc: "Deploy 20 drones.", goal: 20, type: "drones" },
            { id: "matter_synthesizer", title: "Alchemist", desc: "Synthesize 10 Matter.", goal: 10, type: "matter" },
            { id: "ascended_once", title: "The Chosen One", desc: "Perform your first Ascension.", goal: 1, type: "asc" },
            { id: "lucky_id", title: "Lucky Star", desc: "Acquire a lucky UID.", goal: 1, type: "lucky" },
            { id: "hardcore_clicker", title: "Manual Overdrive", desc: "Click 1,000 times.", goal: 1000, type: "clicks_total", reward: "Overdrive Core" },
            { id: "vip_status", title: "Platinum VIP", desc: "Acquire VIP Status.", goal: 1, type: "isVIP" },
            { id: "drone_army", title: "Global Legion", desc: "Own 100 active drones.", goal: 100, type: "drones" },
            { id: "billionaire", title: "Energy Tycoon", desc: "Reach 1,000,000,000 NRG.", goal: 1000000000, type: "energy" }
        ];

        // --- DATA STATE ---
        const corporations = [
            { id: 'neon', name: 'NEON CORP', price: 100, history: [100], volatility: 0.1, color: 0x00ffff },
            { id: 'alpha', name: 'ALPHA TECH', price: 250, history: [250], volatility: 0.05, color: 0xff00ff },
            { id: 'void', name: 'VOID IND', price: 50, history: [50], volatility: 0.2, color: 0x8800ff }
        ];
        let stockPortfolio = { neon: 0, alpha: 0, void: 0 };

        const state = {
            isLoaded: false,
            energy: 0,
            xp: 0,
            level: 1,
            sp: 0,
            storageMax: 400,
            clickPower: 5,
            costs: { click: 50, drone: 150, storage: 250, matter: 1000, plating: 500 },
            inventory: [], // Renamed from items
            achievements: [],
            market: { "Scrap": 15, "Crystal": 60, "Dark Matter": 250, "Cyber Chip": 120 },
            drones: [], // Live drone meshes
            dronesData: [], // Saved drone data
            storageModules: [],
            pipes: [],
            totalCapacity: 400,
            turboActive: false,
            lastTurbo: 0,
            profile: {
                name: "Player",
                avatar: "https://via.placeholder.com/150",
                uid: "00000000",
                lucky: false
            },
            jetpack: { active: false, fuel: 50, cooldown: 0, maxFuel: 50 },
            heat: 0,
            expeditions: [],
            multiplier: 1,
            weather: { type: 'clear', timer: 0 },
            matter: 0,
            antimatter: 0,
            isVIP: false,
            nickColor: "#ffffff",
            playSpeed: 1,
            contracts: [
                { id: 1, title: "Energy Surge", desc: "Reach 50,000 NRG", goal: 50000, reward: 5000, type: "energy", done: false },
                { id: 2, title: "Drone Fleet", desc: "Deploy 10 Drones", goal: 10, reward: 2000, type: "drones", done: false },
                { id: 3, title: "Matter Architect", desc: "Synthesize 5 Matter", goal: 5, reward: 15000, type: "matter", done: false },
                { id: 4, title: "Galaxy Scout", desc: "Complete 5 Expeditions", goal: 5, reward: 8000, type: "exp", done: false }
            ]
        };

        // --- AUTH & PERSISTENCE ---
        function loginWithGoogle() {
            const provider = new firebase.auth.GoogleAuthProvider();
            firebase.auth().signInWithPopup(provider).catch(e => {
                document.getElementById('auth-error').innerText = e.message;
            });
        }

        function loginAnonymous() {
            firebase.auth().signInAnonymously().catch(e => {
                document.getElementById('auth-error').innerText = e.message;
            });
        }

        function loginWithEmail() {
            const email = document.getElementById('auth-email').value;
            const pass = document.getElementById('auth-pass').value;
            if (!email || !pass) {
                document.getElementById('auth-error').innerText = "ENTER CREDENTIALS";
                return;
            }
            firebase.auth().signInWithEmailAndPassword(email, pass).catch(e => {
                if (e.code === 'auth/user-not-found') {
                    return firebase.auth().createUserWithEmailAndPassword(email, pass);
                }
                document.getElementById('auth-error').innerText = e.message;
            });
        }

        let authMode = 'login';
        function toggleAuthMode(mode) {
            authMode = mode;
            document.getElementById('btn-mode-login').style.color = mode === 'login' ? '#0ff' : '#0ff4';
            document.getElementById('btn-mode-login').style.borderBottom = mode === 'login' ? '2px solid #0ff' : 'none';
            document.getElementById('btn-mode-reg').style.color = mode === 'reg' ? '#0ff' : '#0ff4';
            document.getElementById('btn-mode-reg').style.borderBottom = mode === 'reg' ? '2px solid #0ff' : 'none';
            document.getElementById('auth-main-btn').innerText = mode === 'login' ? 'INITIALIZE LINK' : 'CREATE NEURAL LINK';
        }

        function logout() {
            firebase.auth().signOut().then(() => {
                location.reload();
            });
        }

        function handleAuthAction() {
            if (authMode === 'login') loginWithEmail();
            else registerWithEmail();
        }

        function registerWithEmail() {
            const email = document.getElementById('auth-email').value;
            const pass = document.getElementById('auth-pass').value;
            if (!email || !pass) {
                document.getElementById('auth-error').innerText = "ENTER CREDENTIALS";
                return;
            }
            firebase.auth().createUserWithEmailAndPassword(email, pass).catch(e => {
                document.getElementById('auth-error').innerText = e.message;
            });
        }

        firebase.auth().onAuthStateChanged(user => {
            const overlay = document.getElementById('auth-overlay');
            overlay.classList.add('active'); // Keep it visible

            if (user) {
                document.getElementById('auth-inputs').style.display = 'none';
                document.getElementById('auth-selection').style.display = 'none';
                document.getElementById('auth-alt-methods').style.display = 'none';
                document.getElementById('auth-main-btn').style.display = 'none';
                document.getElementById('start-btn-container').style.display = 'block';

                loadGameState();
            } else {
                document.getElementById('auth-inputs').style.display = 'block';
                document.getElementById('auth-selection').style.display = 'block';
                document.getElementById('auth-alt-methods').style.display = 'flex';
                document.getElementById('auth-main-btn').style.display = 'block';
                document.getElementById('start-btn-container').style.display = 'none';
            }
        });

        function runIntroAnimation() {
            const overlay = document.getElementById('auth-overlay');
            const trans = document.getElementById('transition-overlay');
            trans.style.display = 'block';
            trans.style.opacity = '1';

            overlay.style.opacity = '0';
            setTimeout(() => {
                overlay.classList.remove('active');
                overlay.style.display = 'none';
                if (camera) {
                    const startPos = new THREE.Vector3(0, 1500, 1500);
                    camera.position.copy(startPos);
                    const targetPos = new THREE.Vector3(0, 15, 35);
                    let progress = 0;
                    const duration = 300; // frames

                    function animateIntro() {
                        progress++;
                        const t = progress / duration;
                        // Smooth easing: cubic-bezier-ish
                        const ease = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;

                        camera.position.lerpVectors(startPos, targetPos, ease);
                        camera.lookAt(0, 5, 0);

                        // Fade out transition overlay
                        if (progress > duration * 0.5) {
                            trans.style.opacity = 1 - ((progress - duration * 0.5) / (duration * 0.5));
                        }

                        if (progress < duration) requestAnimationFrame(animateIntro);
                        else {
                            trans.style.display = 'none';
                            createToast("ACIS SYSTEM ONLINE");
                        }
                    }
                    animateIntro();
                }
            }, 1000);
        }

        async function saveGameState() {
            if (!state.isLoaded) return;
            const user = firebase.auth().currentUser;
            if (!user) return;
            try {
                // Sync drone data before saving
                state.dronesData = state.drones.map(d => ({
                    type: d.type || 'basic',
                    id: d.mesh.name,
                    hp: d.hp
                }));

                await db.collection("users").doc(user.uid).set({
                    energy: state.energy,
                    xp: state.xp,
                    level: state.level,
                    inventory: state.inventory,
                    costs: state.costs,
                    storageMax: state.storageMax,
                    clickPower: state.clickPower,
                    profile: state.profile,
                    heat: state.heat,
                    expeditions: state.expeditions,
                    matter: state.matter,
                    antimatter: state.antimatter,
                    achievements: state.achievements,
                    dronesData: state.dronesData,
                    isVIP: state.isVIP,
                    lastSeen: firebase.firestore.FieldValue.serverTimestamp(),
                    authType: user.isAnonymous ? 'anonymous' : (user.providerData[0] ? user.providerData[0].providerId : 'email'),
                    email: user.email || 'none'
                }, { merge: true });
                console.log("Acis Sync Complete: " + state.profile.uid);
            } catch (e) { console.error("Sync Error", e); }
        }

        async function linkAccount(type) {
            const user = firebase.auth().currentUser;
            if (!user || !user.isAnonymous) {
                createToast("ALREADY LINKED OR NOT LOGGED IN");
                return;
            }
            const provider = new firebase.auth.GoogleAuthProvider();
            try {
                await user.linkWithPopup(provider);
                createToast("ACCOUNT LINKED SUCCESSFULLY");
                saveGameState();
            } catch (e) { createToast("LINK ERROR: " + e.message); }
        }

        function generateUID() {
            const chars = '0123456789ABCDEF';
            let res = '';
            for(let i=0; i<8; i++) res += chars[Math.floor(Math.random()*chars.length)];
            return res;
        }

        function isLuckyUID(uid) {
            const counts = {};
            for(const c of uid) counts[c] = (counts[c] || 0) + 1;
            return Object.values(counts).some(v => v >= 4) || / (0123|1234|4321|ABCD|1111|7777) /.test(uid);
        }

        let userUnsubscribe = null;
        async function loadGameState() {
            const user = firebase.auth().currentUser;
            if (!user) return;

            if (userUnsubscribe) userUnsubscribe();

            userUnsubscribe = db.collection("users").doc(user.uid).onSnapshot(doc => {
                if (doc.exists) {
                    const data = doc.data();

                    // For energy, we only update if the difference is large to avoid overwrite loops
                    if (Math.abs(state.energy - (data.energy || 0)) > 100 || !state.isLoaded) {
                        state.energy = data.energy || 0;
                    }

                    state.xp = data.xp || 0;
                    state.level = data.level || 1;
                    state.inventory = data.inventory || data.items || [];
                    state.costs = data.costs || state.costs;
                    state.storageMax = data.storageMax || state.storageMax;
                    state.clickPower = data.clickPower || state.clickPower;
                    state.profile = data.profile || state.profile;
                    state.heat = data.heat || 0;
                    state.expeditions = data.expeditions || [];
                    state.matter = data.matter || 0;
                    state.antimatter = data.antimatter || 0;
                    state.achievements = data.achievements || [];
                    state.isVIP = data.isVIP || false;

                    if (!state.isLoaded) {
                        state.dronesData = data.dronesData || [];
                        if (state.drones.length === 0 && state.dronesData.length > 0) {
                            state.dronesData.forEach(d => {
                                spawnDrone(d.type);
                                const active = state.drones[state.drones.length - 1];
                                if (active && d.hp !== undefined) active.hp = d.hp;
                            });
                        }

                        if (!state.profile.uid || state.profile.uid === "00000000") {
                            state.profile.uid = generateUID();
                            state.profile.lucky = isLuckyUID(state.profile.uid);
                        }

                        state.isLoaded = true;
                        createToast("NEURAL SYNC COMPLETE");
                    }

                    document.getElementById('profile-name-span').innerText = state.profile.name;
                    document.getElementById('profile-avatar-img').src = state.profile.avatar;
                    document.getElementById('modal-avatar-img').src = state.profile.avatar;
                    document.getElementById('display-id').innerText = state.profile.uid;

                    updateUI();
                    updateInventoryUI();
                } else {
                    state.profile.uid = generateUID();
                    state.profile.lucky = isLuckyUID(state.profile.uid);
                    state.isLoaded = true;
                    saveGameState();
                }
            }, e => console.error("Snapshot Error", e));
        }

        // --- ENGINE ---
        const GAME_VERSION = "5.0.0";
        let scene, camera, renderer, raycaster, mouse, clock;
        let settlements = [];
        let core, mainTankLiquid, skillGroup, moduleGroup, particles;
        let worldGroup, roomGroup, galaxyGroup;
        let isSkillMode = false, keys = {}, isRightMB = false;
        let lastCameraState = { pos: new THREE.Vector3(), quat: new THREE.Quaternion(), look: new THREE.Euler() };
        let lookRotation = new THREE.Euler(0, 0, 0, 'YXZ');

        function init() {
            scene = new THREE.Scene();
            scene.background = new THREE.Color(0x00050a);
            scene.fog = new THREE.FogExp2(0x00050a, 0.015);

            camera = new THREE.PerspectiveCamera(65, window.innerWidth / window.innerHeight, 0.1, 2000);
            camera.position.set(0, 15, 35);

            renderer = new THREE.WebGLRenderer({ antialias: true, logarithmicDepthBuffer: true, powerPreference: "high-performance" });
            renderer.setSize(window.innerWidth, window.innerHeight);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)); // High quality but capped
            document.body.appendChild(renderer.domElement);

            raycaster = new THREE.Raycaster();
            mouse = new THREE.Vector2();
            clock = new THREE.Clock();

            // Lighting
            const amb = new THREE.AmbientLight(0x4040ff, 0.2);
            amb.name = "AMBIENT";
            scene.add(amb);

            const pLight = new THREE.PointLight(0x00ffff, 2, 150);
            pLight.name = "MAIN_LIGHT";
            pLight.position.set(20, 30, 10);
            scene.add(pLight);

            const emerLight = new THREE.PointLight(0xff0000, 0, 100);
            emerLight.name = "EMERGENCY_LIGHT";
            emerLight.position.set(0, 20, 0);
            scene.add(emerLight);

            // 1. CORE ENGINE (Ядро)
            const coreGeometry = new THREE.IcosahedronGeometry(4, 2);
            const coreMaterial = new THREE.MeshStandardMaterial({
                color: 0x00ffff,
                emissive: 0x00ffff,
                emissiveIntensity: 0.5,
                wireframe: true,
                transparent: true,
                opacity: 0.8
            });
            core = new THREE.Mesh(coreGeometry, coreMaterial);

            const coreOuter = new THREE.Mesh(
                new THREE.IcosahedronGeometry(4.5, 1),
                new THREE.MeshStandardMaterial({ color: 0xff00ff, wireframe: true, transparent: true, opacity: 0.3 })
            );
            core.add(coreOuter);

            const coreInner = new THREE.Mesh(
                new THREE.SphereGeometry(2.8, 32, 32),
                new THREE.MeshPhongMaterial({ color: 0x00ffff, emissive: 0x008888, shininess: 100 })
            );
            core.add(coreInner);
            core.position.set(-15, 5, 0);
            core.name = "CORE";
            scene.add(core);

            // 2. PRIMARY STORAGE
            const tankRoot = new THREE.Group();
            tankRoot.position.set(15, 0, 0);
            scene.add(tankRoot);

            const glassMat = new THREE.MeshPhysicalMaterial({
                transmission: 0.3,
                opacity: 0.4,
                transparent: true,
                roughness: 0.1,
                metalness: 0.9,
                color: 0xccffff
            });

            const glassBase = new THREE.Mesh(new THREE.CylinderGeometry(4, 4, 12, 32, 1, true), glassMat);
            glassBase.position.y = 6;
            tankRoot.add(glassBase);

            // Structural Caps
            const capGeo = new THREE.CylinderGeometry(4.5, 4.5, 1, 32);
            const capMat = new THREE.MeshStandardMaterial({ color: 0x333333, metalness: 1, roughness: 0.2 });
            const topCap = new THREE.Mesh(capGeo, capMat);
            topCap.position.y = 12;
            tankRoot.add(topCap);
            const botCap = topCap.clone();
            botCap.position.y = 0;
            tankRoot.add(botCap);

            // Internal Rod
            const rod = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.5, 12, 16), new THREE.MeshStandardMaterial({color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 2}));
            rod.position.y = 6;
            tankRoot.add(rod);

            mainTankLiquid = new THREE.Mesh(
                new THREE.CylinderGeometry(3.9, 3.9, 11.8, 32),
                new THREE.MeshStandardMaterial({
                    color: 0x00ffff,
                    emissive: 0x00ffff,
                    emissiveIntensity: 0.6,
                    transparent: true,
                    opacity: 0.7
                })
            );
            mainTankLiquid.geometry.translate(0, 5.9, 0);
            mainTankLiquid.scale.y = 0.01;
            tankRoot.add(mainTankLiquid);

            // 3. GROUPS
            moduleGroup = new THREE.Group();
            scene.add(moduleGroup);
            skillGroup = new THREE.Group();
            skillGroup.position.set(0, 500, 0);
            scene.add(skillGroup);
            createSkillTree();

            // Particles for Energy Overload
            const pCount = 200;
            const pGeo = new THREE.BufferGeometry();
            const pPos = new Float32Array(pCount * 3);
            for(let i=0; i<pCount*3; i++) pPos[i] = (Math.random() - 0.5) * 10;
            pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
            particles = new THREE.Points(pGeo, new THREE.PointsMaterial({color: 0x00ffff, size: 0.1}));
            particles.visible = false;
            scene.add(particles);

            // World Layers
            worldGroup = new THREE.Group();
            scene.add(worldGroup);

            roomGroup = new THREE.Group();
            worldGroup.add(roomGroup);

            galaxyGroup = new THREE.Group();
            galaxyGroup.visible = false;
            scene.add(galaxyGroup);

            // Room Elements
            const roomGeo = new THREE.BoxGeometry(200, 100, 200);
            const roomMat = new THREE.MeshStandardMaterial({ color: 0x111111, side: THREE.BackSide });
            const room = new THREE.Mesh(roomGeo, roomMat);
            room.position.y = 49;
            roomGroup.add(room);

            // Galaxy Elements
            const starGeo = new THREE.BufferGeometry();
            const starPos = new Float32Array(3000 * 3);
            for(let i=0; i<9000; i++) starPos[i] = (Math.random()-0.5) * 5000;
            starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
            const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({color:0xffffff, size: 2}));
            galaxyGroup.add(stars);

            // Move existing groups to worldGroup
            worldGroup.add(core);
            worldGroup.add(tankRoot);
            worldGroup.add(moduleGroup);

            // Crown
            const crownGroup = new THREE.Group();
            crownGroup.name = "CROWN";
            scene.add(crownGroup);
            if (state.antimatter > 0) {
                const crownGeo = new THREE.TorusGeometry(1, 0.1, 16, 100);
                const crownMat = new THREE.MeshStandardMaterial({color: 0xffd700, emissive: 0xffd700, emissiveIntensity: 2});
                const crown = new THREE.Mesh(crownGeo, crownMat);
                crown.rotation.x = Math.PI / 2;
                crown.position.y = 12;
                crownGroup.add(crown);
                crownGroup.position.set(-15, 0, 0);
            }

            // Central Platform
            const platformGeo = new THREE.CylinderGeometry(40, 42, 2, 6);
            const platformMat = new THREE.MeshStandardMaterial({ color: 0x111111, roughness: 0.2, metalness: 0.8 });
            const platform = new THREE.Mesh(platformGeo, platformMat);
            platform.position.y = -1;
            worldGroup.add(platform);

            const stripeGeo = new THREE.TorusGeometry(38, 0.2, 8, 6);
            const stripeMat = new THREE.MeshStandardMaterial({ color: 0x8800ff, emissive: 0x8800ff, emissiveIntensity: 2 });
            const stripe = new THREE.Mesh(stripeGeo, stripeMat);
            stripe.rotation.x = Math.PI / 2;
            stripe.position.y = 0.1;
            platform.add(stripe);

            // Grid
            const grid = new THREE.GridHelper(500, 50, 0x004444, 0x001111);
            grid.position.y = -0.1;
            worldGroup.add(grid);

            // Events
            window.addEventListener('mousedown', (e) => {
                if(e.button === 0) checkClick();
                if(e.button === 1) { // MMB Pointer Lock Toggle
                    if (document.pointerLockElement) {
                        document.exitPointerLock();
                    } else {
                        renderer.domElement.requestPointerLock();
                    }
                }
                if(e.button === 2) isRightMB = true;
            });
            window.addEventListener('mouseup', (e) => { if(e.button === 2) isRightMB = false; });
            window.addEventListener('mousemove', onMouseMove);
            window.addEventListener('keydown', onKeyDown);
            window.addEventListener('keyup', (e) => keys[e.code] = false);
            window.addEventListener('wheel', (e) => {
                camera.fov = Math.max(30, Math.min(90, camera.fov + e.deltaY * 0.05));
                camera.updateProjectionMatrix();
            });
            window.addEventListener('resize', () => {
                camera.aspect = window.innerWidth / window.innerHeight;
                camera.updateProjectionMatrix();
                renderer.setSize(window.innerWidth, window.innerHeight);
            });

            animate();
            startSystems();
            // Removed redundant loadGameState() - handled by auth observer
            setInterval(saveGameState, 60000); // Auto-save every minute
        }

        function createSkillTree() {
            const nodes = [
                { id: 0, pos: [0, 0, 0], name: "NEURAL HUB" },
                { id: 1, pos: [-15, 10, -10], name: "QUANTUM EFFICIENCY" },
                { id: 2, pos: [15, 10, -10], name: "MATTER OVERDRIVE" },
                { id: 3, pos: [0, 25, -20], name: "SINGULARITY" },
                { id: 4, pos: [-25, 15, 0], name: "DRONE SWARM" },
                { id: 5, pos: [25, 15, 0], name: "PHOTON BURST" },
                { id: 6, pos: [0, 40, -30], name: "GALAXY HARVEST" }
            ];
            const edges = [[0,1], [0,2], [1,3], [2,3], [1,4], [2,5], [3,6]];

            nodes.forEach(n => {
                const mesh = new THREE.Mesh(
                    new THREE.IcosahedronGeometry(2.5, 0),
                    new THREE.MeshStandardMaterial({color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 0.2, wireframe: true})
                );
                mesh.position.set(...n.pos);
                mesh.userData = n;
                skillGroup.add(mesh);

                const center = new THREE.Mesh(new THREE.SphereGeometry(0.8), new THREE.MeshBasicMaterial({color: 0xff00ff}));
                mesh.add(center);
            });

            edges.forEach(e => {
                const p1 = new THREE.Vector3(...nodes[e[0]].pos);
                const p2 = new THREE.Vector3(...nodes[e[1]].pos);
                const dir = p2.clone().sub(p1);
                const pipe = new THREE.Mesh(
                    new THREE.CylinderGeometry(0.4, 0.4, dir.length(), 8),
                    new THREE.MeshStandardMaterial({color: 0x111111, emissive: 0x00ffff, emissiveIntensity: 0.5})
                );
                pipe.position.copy(p1).add(dir.multiplyScalar(0.5));
                pipe.quaternion.setFromUnitVectors(new THREE.Vector3(0,1,0), dir.clone().normalize());
                skillGroup.add(pipe);
                state.pipes.push(pipe);
            });
        }

        function addModule() {
            const index = state.storageModules.length;
            const dist = 25;
            const angle = index * (Math.PI * 0.4);
            const x = Math.cos(angle) * dist;
            const z = Math.sin(angle) * dist;

            const group = new THREE.Group();
            group.position.set(x, 0, z);
            moduleGroup.add(group);

            const glass = new THREE.Mesh(new THREE.CylinderGeometry(2.5, 2.5, 8, 24, 1, true),
                new THREE.MeshPhysicalMaterial({ transmission: 0.3, opacity: 0.4, transparent: true, color: 0x88ffff, roughness: 0.1, metalness: 0.9 }));
            glass.position.y = 4;
            group.add(glass);

            // Module Caps
            const modCapGeo = new THREE.CylinderGeometry(2.8, 2.8, 0.6, 24);
            const modCapMat = new THREE.MeshStandardMaterial({ color: 0x222222, metalness: 1, roughness: 0.2 });
            const mTop = new THREE.Mesh(modCapGeo, modCapMat);
            mTop.position.y = 8;
            group.add(mTop);
            const mBot = mTop.clone();
            mBot.position.y = 0;
            group.add(mBot);

            // Internal Core
            const coreRod = new THREE.Mesh(new THREE.IcosahedronGeometry(1, 0), new THREE.MeshStandardMaterial({color:0x00ffff, emissive:0x00ffff, emissiveIntensity:2}));
            coreRod.position.y = 4;
            group.add(coreRod);

            const liq = new THREE.Mesh(new THREE.CylinderGeometry(2.4, 2.4, 7.8, 24),
                new THREE.MeshStandardMaterial({ color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 0.4, transparent: true, opacity: 0.8 }));
            liq.geometry.translate(0, 3.9, 0);
            liq.scale.y = 0.01;
            group.add(liq);

            state.storageModules.push({ group, liq });

            // 3D Cable
            const cableCurve = new THREE.CubicBezierCurve3(
                new THREE.Vector3(-15, 5, 0),
                new THREE.Vector3(-5, 12, z/2),
                new THREE.Vector3(x/2, 12, z/2),
                new THREE.Vector3(x, 8, z)
            );
            const cableGeo = new THREE.TubeGeometry(cableCurve, 20, 0.1, 8, false);
            const cableMat = new THREE.MeshStandardMaterial({ color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 0.5 });
            const cable = new THREE.Mesh(cableGeo, cableMat);
            scene.add(cable);
            state.storageModules[state.storageModules.length-1].cable = cable;
        }

        let activeDrone = null;
        function showDroneMenu(drone) {
            activeDrone = drone;
            const menu = document.getElementById('drone-menu');
            menu.style.display = 'block';
            updateDroneMenuPos();
        }

        function updateDroneMenuPos() {
            if (!activeDrone) return;
            const menu = document.getElementById('drone-menu');
            const worldPos = new THREE.Vector3();
            activeDrone.getWorldPosition(worldPos);
            const vector = worldPos.project(camera);
            const x = (vector.x + 1) * window.innerWidth / 2;
            const y = -(vector.y - 1) * window.innerHeight / 2;
            menu.style.left = (x - 75) + 'px';
            menu.style.top = (y - 100) + 'px';
        }

        function sendDroneExp(hours) {
            if (state.energy >= 500 * hours) {
                state.energy -= 500 * hours;
                const endTime = Date.now() + (hours * 3600000);
                state.expeditions.push({ end: endTime, claimed: false });
                createToast(`EXPEDITION STARTED: ${hours}H`);
                document.getElementById('drone-menu').style.display = 'none';
                activeDrone = null;
                updateUI();
            } else {
                createToast("NOT ENOUGH ENERGY");
            }
        }

        function spawnDrone(type = 'basic') {
            const drone = new THREE.Group();
            drone.name = "DRONE_" + Math.random().toString(36).substr(2, 5);

            let coreColor = 0x00ffff;
            let hp = 100;
            let multiplier = 1;
            let speed = 1;
            let range = 30;

            if (type === 'mega') { coreColor = 0xff00ff; multiplier = 2.5; }
            if (type === 'legendary') { coreColor = 0xffd700; multiplier = 5; }
            if (type === 'fragile') { coreColor = 0xff4444; multiplier = 4; speed = 1.2; hp = 30; }
            if (type === 'tank') { coreColor = 0x4444ff; multiplier = 0.5; hp = 500; }
            if (type === 'scavenger') { coreColor = 0x44ff44; multiplier = 0.8; }
            if (type === 'turbo') { coreColor = 0xffff44; multiplier = 1.5; speed = 2; }
            if (type === 'vip') { coreColor = 0xffd700; multiplier = 10; hp = 10000000; } // 10M HP

            // Sphere Core
            const body = new THREE.Mesh(new THREE.SphereGeometry(0.4, 16, 16), new THREE.MeshStandardMaterial({color: coreColor, emissive: coreColor, emissiveIntensity: 2}));
            drone.add(body);

            // Octahedron Frame
            const frame = new THREE.Mesh(new THREE.OctahedronGeometry(0.6, 0), new THREE.MeshStandardMaterial({color: 0x222222, wireframe: true}));
            drone.add(frame);

            // Rotating Rings
            const ring1 = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.04, 8, 32), new THREE.MeshStandardMaterial({color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 0.5}));
            ring1.rotation.x = Math.PI/2;
            drone.add(ring1);

            const ring2 = new THREE.Mesh(new THREE.TorusGeometry(1.1, 0.02, 8, 32), new THREE.MeshStandardMaterial({color: 0xff00ff, emissive: 0xff00ff, emissiveIntensity: 0.5}));
            ring2.rotation.y = Math.PI/2;
            drone.add(ring2);

            // Side Thrusters (little cubes)
            for(let i=0; i<4; i++) {
                const t = new THREE.Mesh(new THREE.BoxGeometry(0.2, 0.2, 0.2), new THREE.MeshStandardMaterial({color: 0x444444}));
                const angle = (i/4) * Math.PI * 2;
                t.position.set(Math.cos(angle)*0.7, 0, Math.sin(angle)*0.7);
                drone.add(t);
            }

            // Light
            const light = new THREE.PointLight(0x00ffff, 1, 15);
            drone.add(light);

            scene.add(drone);

            const laserGeo = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]);
            const laser = new THREE.Line(laserGeo, new THREE.LineBasicMaterial({color: 0xff00ff, transparent: true, opacity: 0}));
            scene.add(laser);

            state.drones.push({
                mesh: drone, laser, light, ring1, ring2,
                timer: Math.random() * 10, type, hp, maxHp: hp,
                multiplier, speed, range
            });
        }

        function checkClick() {
            if (isQMenuOpen || isTMenuOpen) return;
            raycaster.setFromCamera(mouse, camera);

            // Random Drone Drop Logic
            if (Math.random() < 0.001) { // 0.1% chance on click
                const types = ['fragile', 'tank', 'scavenger', 'turbo'];
                const type = types[Math.floor(Math.random()*types.length)];
                state.inventory.push(type.charAt(0).toUpperCase() + type.slice(1) + " Drone");
                createToast("RARE DROP: NEW DRONE FOUND!");
                updateInventoryUI();
            }

            if (isSkillMode) {
                const hits = raycaster.intersectObjects(skillGroup.children, true);
                if (hits.length > 0) {
                    let obj = hits[0].object;
                    while (obj && !obj.userData.name) obj = obj.parent;
                    if (obj) buySkill(obj);
                }
                return;
            }

            if (traderDrone) {
                const traderHits = raycaster.intersectObject(traderDrone.mesh, true);
                if (traderHits.length > 0) {
                    toggleMenu('market');
                    return;
                }
            }

            const stockHits = raycaster.intersectObject(scene.getObjectByName("STOCK_TERMINAL"), true);
            if (stockHits.length > 0) {
                toggleMenu('stock-market');
                updateStockUI();
                return;
            }

            const droneHits = raycaster.intersectObjects(state.drones.map(d => d.mesh), true);
            if (droneHits.length > 0) {
                let dGroup = droneHits[0].object;
                while(dGroup && !dGroup.name.startsWith("DRONE_")) dGroup = dGroup.parent;
                if (dGroup) {
                    showDroneMenu(dGroup);
                    return;
                }
            }

            const hits = raycaster.intersectObject(core, true);
            if(hits.length > 0) {
                let clickBonus = state.weather.type === 'solar_flare' ? 10 : 1;
                let antiMult = Math.pow(2, state.antimatter);
                state.energy += state.clickPower * clickBonus * antiMult;
                addXP(10);
                core.scale.set(1.15, 1.15, 1.15);
                core.children[1].material.emissiveIntensity = 10;
                setTimeout(() => { if(core.children[1]) core.children[1].material.emissiveIntensity = 0.5; }, 50);

                showLootPop(hits[0].point);

                let scavMult = 1;
                state.drones.forEach(d => { if(d.type === 'scavenger') scavMult += 0.2; });

                if(Math.random() < 0.15 * scavMult) {
                    const keys = Object.keys(state.market);
                    const found = keys[Math.floor(Math.random()*keys.length)];
                    state.inventory.push(found);
                    createToast(`FOUND: ${found.toUpperCase()}`);
                }
                updateUI();
            }
        }

        function buySkill(node) {
            const cost = 1000;
            if (state.energy >= cost && !node.userData.active) {
                state.energy -= cost;
                node.userData.active = true;
                node.children.forEach(c => {
                    if (c.material) c.material.color.set(0x00ff00);
                });
                state.clickPower += 15;
                createToast(`UNLOCKED: ${node.userData.name}`);
                updateUI();
            } else if (node.userData.active) {
                createToast("ALREADY ACTIVE");
            } else {
                createToast("NOT ENOUGH ENERGY");
            }
        }

        function showLootPop(pos) {
            const div = document.createElement('div');
            div.className = 'loot-pop';
            div.innerText = `+${state.clickPower} NRG`;
            div.style.left = mouse.x * 50 + 50 + "%";
            div.style.top = -mouse.y * 50 + 50 + "%";
            document.getElementById('ui-layer').appendChild(div);
            setTimeout(() => div.remove(), 1000);
        }

        function createToast(txt) {
            const t = document.createElement('div');
            t.style.cssText = "position:absolute; bottom:100px; right:20px; color:#0ff; background:rgba(0,0,0,0.8); padding:10px; border-right:3px solid #0ff; animation: float-up 2s forwards;";
            t.innerText = txt;
            document.body.appendChild(t);
            setTimeout(() => t.remove(), 2000);
        }

        function createExplosion(pos) {
            const count = 50;
            const geometry = new THREE.BufferGeometry();
            const positions = new Float32Array(count * 3);
            const velocities = [];

            for (let i = 0; i < count; i++) {
                positions[i * 3] = pos.x;
                positions[i * 3 + 1] = pos.y;
                positions[i * 3 + 2] = pos.z;
                velocities.push(new THREE.Vector3(
                    (Math.random() - 0.5) * 2,
                    (Math.random() - 0.5) * 2,
                    (Math.random() - 0.5) * 2
                ));
            }

            geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
            const material = new THREE.PointsMaterial({ color: 0xffaa00, size: 0.5, transparent: true });
            const points = new THREE.Points(geometry, material);
            scene.add(points);

            let lifetime = 60;
            const animateExplosion = () => {
                lifetime--;
                const posAttr = geometry.attributes.position;
                for (let i = 0; i < count; i++) {
                    posAttr.array[i * 3] += velocities[i].x;
                    posAttr.array[i * 3 + 1] += velocities[i].y;
                    posAttr.array[i * 3 + 2] += velocities[i].z;
                }
                posAttr.needsUpdate = true;
                material.opacity = lifetime / 60;

                if (lifetime > 0) {
                    requestAnimationFrame(animateExplosion);
                } else {
                    scene.remove(points);
                    geometry.dispose();
                    material.dispose();
                }
            };
            animateExplosion();
        }

        function onMouseMove(e) {
            mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;

            if (document.pointerLockElement === renderer.domElement) {
                lookRotation.y -= e.movementX * 0.002;
                lookRotation.x -= e.movementY * 0.002;
                lookRotation.x = Math.max(-Math.PI/2, Math.min(Math.PI/2, lookRotation.x));
                camera.quaternion.setFromEuler(lookRotation);
            } else if(isRightMB) {
                lookRotation.y -= e.movementX * 0.004;
                lookRotation.x -= e.movementY * 0.004;
                camera.quaternion.setFromEuler(lookRotation);
            }
        }

        function onKeyDown(e) {
            keys[e.code] = true;
            const key = e.key.toLowerCase();

            if (isTMenuOpen) {
                if (key === 'w') changeTLevel(1);
                if (key === 's') changeTLevel(-1);
                if (key === 't') toggleLeveling();
                return;
            }

            if(e.code === 'KeyH') toggleMenu('shop');
            if(e.code === 'KeyQ') toggleProfile();
            if(e.code === 'KeyR') toggleAchievements();
            if(e.code === 'KeyT') toggleLeveling();
            if(e.code === 'KeyM') toggleTrading();
            if(e.code === 'KeyZ') {
                if (camera.position.y < 1000) {
                    camera.position.set(0, 3000, 3000);
                    camera.lookAt(0,0,0);
                    galaxyGroup.visible = true;
                } else {
                    camera.position.set(0, 15, 35);
                    galaxyGroup.visible = false;
                }
            }
            if(e.code === 'ShiftLeft') {
                if (state.jetpack.cooldown <= 0) {
                    state.jetpack.active = !state.jetpack.active;
                    createToast(state.jetpack.active ? "JETPACK ON" : "JETPACK OFF");
                } else {
                    createToast(`COOLDOWN: ${Math.ceil(state.jetpack.cooldown)}s`);
                }
            }
            if(e.code === 'KeyT') {
                const now = Date.now();
                if (now - state.lastTurbo > 30000) {
                    state.turboActive = true;
                    state.lastTurbo = now;
                    createToast("HYPER-CORE OVERDRIVE ACTIVE!");
                    setTimeout(() => {
                        state.turboActive = false;
                        createToast("OVERDRIVE COOLING DOWN...");
                    }, 10000);
                } else {
                    createToast("OVERDRIVE ON COOLDOWN");
                }
            }
            if(e.code === 'KeyE') {
                isSkillMode = !isSkillMode;
                if(isSkillMode) {
                    lastCameraState.pos.copy(camera.position);
                    lastCameraState.quat.copy(camera.quaternion);
                    lastCameraState.look.copy(lookRotation);

                    camera.position.set(0, 520, 60);
                    camera.lookAt(0, 500, 0);
                } else {
                    camera.position.copy(lastCameraState.pos);
                    camera.quaternion.copy(lastCameraState.quat);
                    lookRotation.copy(lastCameraState.look);
                }
            }
        }

        let traderDrone = null;
        function spawnTrader() {
            if (traderDrone) return;
            const drone = new THREE.Group();
            const body = new THREE.Mesh(new THREE.SphereGeometry(0.8, 16, 16), new THREE.MeshStandardMaterial({color: 0x000000, emissive: 0xff00ff, emissiveIntensity: 2}));
            drone.add(body);
            const frame = new THREE.Mesh(new THREE.OctahedronGeometry(1.2, 0), new THREE.MeshStandardMaterial({color: 0xff00ff, wireframe: true}));
            drone.add(frame);
            drone.position.set(0, 20, -30);
            scene.add(drone);
            traderDrone = { mesh: drone, timer: 0 };
            createToast("BLACK MARKET TRADER HAS ARRIVED");
        }

        function buyMarketUpgrade(type) {
            if (state.storageMax < 6000) {
                createToast("STORAGE TOO LOW");
                return;
            }
            if (type === 'mult') {
                state.storageMax -= 5000;
                state.multiplier += 5;
                createToast("DEAL SEALED: MULTIPLIER BOOSTED");
            } else if (type === 'matter') {
                state.storageMax -= 2000;
                state.matter += 10;
                createToast("DEAL SEALED: MATTER ACQUIRED");
            }
            updateUI();
            saveGameState();
        }

        function buyUpgrade(type) {
            let cost = state.costs[type];
            // Special costs for new items
            if (type === 'vip_status') cost = 1000000000;
            if (type === 'vip_drone') cost = 100000000000;
            if (type === 'nick_color') cost = 1000000;

            if(state.energy >= cost) {
                state.energy -= cost;
                if(type === 'click') {
                    state.clickPower += 5;
                    state.costs.click = Math.round(state.costs.click * 1.8);
                } else if(type === 'drone') {
                    spawnDrone();
                    state.costs.drone = Math.round(state.costs.drone * 1.7);
                } else if(type === 'storage') {
                    state.storageMax += 5000;
                    addModule();
                    state.costs.storage = Math.round(state.costs.storage * 1.35);
                } else if(type === 'matter') {
                    state.costs.matter = Math.round(state.costs.matter * 2.5);
                    createToast("MATTER CORE UPGRADED");
                } else if(type === 'plating') {
                    state.costs.plating = Math.round(state.costs.plating * 2);
                    createToast("PLATING REINFORCED");
                } else if(type === 'vip_status') {
                    state.isVIP = true;
                    createToast("VIP PLATINUM STATUS ACQUIRED!");
                } else if(type === 'vip_drone') {
                    spawnDrone('vip');
                    createToast("VIP GOLDEN DRONE DEPLOYED!");
                } else if(type === 'nick_color') {
                    state.nickColor = document.getElementById('nick-color-picker').value;
                    createToast("NEON COLOR APPLIED");
                }
                updateUI();
            } else if (type === 'void' && state.matter >= 5) {
                state.matter -= 5;
                state.multiplier *= 2;
                createToast("VOID SINGULARITY INSTALLED");
                updateUI();
            }
        }

        function useItem(idx) {
            const name = state.inventory[idx];
            const item = ITEMS[name];
            if (item && item.type === "usable") {
                item.effect(state);
                state.inventory.splice(idx, 1);
                createToast(`USED: ${name.toUpperCase()}`);
            } else if (item && item.type === "drone") {
                spawnDrone(item.droneType);
                state.inventory.splice(idx, 1);
                createToast(`DEPLOYED: ${name.toUpperCase()}`);
            } else {
                return createToast("NOT USABLE");
            }
            updateInventoryUI();
            updateUI();
            saveGameState();
        }

        function sellItem(idx) {
            const name = state.inventory[idx];
            const item = ITEMS[name];
            state.energy += item ? item.value : 10;
            state.inventory.splice(idx, 1);
            updateInventoryUI();
            updateUI();
            saveGameState();
        }

        let isQMenuOpen = false;
        function toggleProfile() {
            const overlay = document.getElementById('profile-overlay');
            isQMenuOpen = overlay.style.display !== 'flex';
            overlay.style.display = isQMenuOpen ? 'flex' : 'none';

            if (isQMenuOpen) {
                document.body.classList.add('ui-active');
                document.getElementById('q-nick-display').innerText = state.profile.name;
                document.getElementById('q-avatar-img').style.backgroundImage = `url(${state.profile.avatar})`;
                const user = firebase.auth().currentUser;
                if (user) {
                    document.getElementById('link-btn-q').style.display = user.isAnonymous ? 'block' : 'none';
                }
                updateInventoryUI();
                initQMenu3D();
            } else {
                document.body.classList.remove('ui-active');
                if (qMenuRenderer) {
                    qMenuRenderer.dispose();
                    document.getElementById('q-canvas-container').innerHTML = '';
                    qMenuRenderer = null;
                }
            }
        }

        let qMenuRenderer, qMenuScene, qMenuCamera, qMenuCore;
        function initQMenu3D() {
            if (qMenuRenderer) return;
            const container = document.getElementById('q-canvas-container');
            qMenuScene = new THREE.Scene();
            qMenuCamera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
            qMenuCamera.position.z = 5;

            qMenuRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
            qMenuRenderer.setSize(window.innerWidth, window.innerHeight);
            container.appendChild(qMenuRenderer.domElement);

            const geo = new THREE.IcosahedronGeometry(2, 1);
            const mat = new THREE.MeshPhongMaterial({
                color: 0x00f2ff, wireframe: true, emissive: 0x00f2ff, emissiveIntensity: 0.5
            });
            qMenuCore = new THREE.Mesh(geo, mat);
            qMenuScene.add(qMenuCore);

            const light = new THREE.PointLight(0x00f2ff, 1, 100);
            light.position.set(5, 5, 5);
            qMenuScene.add(light);
            qMenuScene.add(new THREE.AmbientLight(0x111111));

            function animateQ() {
                if (!isQMenuOpen) return;
                requestAnimationFrame(animateQ);
                qMenuCore.rotation.y += 0.01;
                qMenuCore.rotation.z += 0.005;
                qMenuRenderer.render(qMenuScene, qMenuCamera);
            }
            animateQ();
        }

        function setAvatar(url) {
            document.getElementById('avatar-input').value = url;
            document.getElementById('modal-avatar-img').src = url;
        }

        function uploadAvatar(input) {
            const file = input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                setAvatar(e.target.result);
                createToast("AVATAR LOADED");
            };
            reader.readAsDataURL(file);
        }

        async function updateProfile() {
            state.profile.name = document.getElementById('nick-input').value || "Player";
            state.profile.avatar = document.getElementById('avatar-input').value || "https://via.placeholder.com/150";

            document.getElementById('profile-name-span').innerText = state.profile.name;
            document.getElementById('profile-avatar-img').src = state.profile.avatar;
            document.getElementById('modal-avatar-img').src = state.profile.avatar;

            // Optional: Save avatar to public gallery collection
            if (state.profile.avatar.startsWith('data:')) {
                const user = firebase.auth().currentUser;
                await db.collection("avatars").doc(user.uid).set({
                    url: state.profile.avatar,
                    owner: state.profile.name
                });
            }

            createToast("NEURAL DATA UPDATED");
            saveGameState();
        }

        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('content-' + tab).style.display = 'block';
            document.getElementById('tab-btn-' + tab).classList.add('active');
        }

        function toggleAchievements() {
            const overlay = document.getElementById('achievements-overlay');
            const isOpening = overlay.style.display !== 'flex';
            overlay.style.display = isOpening ? 'flex' : 'none';
            if (isOpening) renderAchievementGrid();
        }

        function renderAchievementGrid() {
            const grid = document.getElementById('ach-grid');
            grid.innerHTML = '';
            ACHIEVEMENTS.forEach(ach => {
                const isUnlocked = state.achievements.includes(ach.id);
                const div = document.createElement('div');
                div.style.cssText = `background:rgba(0,255,255,${isUnlocked ? '0.1' : '0.02'}); border:1px solid ${isUnlocked ? '#0ff' : '#333'}; padding:15px; border-radius:12px; text-align:center; transition:0.3s; cursor:pointer; position:relative;`;
                div.innerHTML = `
                    <div id="medal-${ach.id}" style="height:100px; width:100px; margin:0 auto 10px;"></div>
                    <b style="color:${isUnlocked ? '#0ff' : '#555'}; font-size:0.6rem;">${ach.title}</b>
                    <div class="ach-detail" style="display:none; position:absolute; top:110%; left:0; right:0; background:rgba(0,10,20,0.95); border:1px solid #0ff; padding:10px; z-index:100; font-size:0.6rem; text-align:left; backdrop-filter:blur(10px); box-shadow:0 0 20px #0ff4;">
                        <b style="color:#0ff; text-transform:uppercase;">${ach.title}</b><br>
                        <p style="margin:5px 0; color:#aaa;">${ach.desc}</p>
                        <span style="color:${isUnlocked ? '#0f0' : '#f00'}; font-weight:bold;">${isUnlocked ? '✓ SECURED' : '⚠ ENCRYPTED'}</span>
                    </div>
                `;
                div.onclick = (e) => {
                    const detail = div.querySelector('.ach-detail');
                    const isVisible = detail.style.display === 'block';
                    document.querySelectorAll('.ach-detail').forEach(d => d.style.display = 'none');
                    detail.style.display = isVisible ? 'none' : 'block';
                };
                grid.appendChild(div);

                initMedal3D(`medal-${ach.id}`, ach.id, isUnlocked);
            });
        }

        function initMedal3D(containerId, id, unlocked) {
            const container = document.getElementById(containerId);
            if (!container) return;
            const sceneMedal = new THREE.Scene();
            const cameraMedal = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
            cameraMedal.position.z = 4;
            const rendererMedal = new THREE.WebGLRenderer({ antialias: true, alpha: true });
            rendererMedal.setSize(100, 100);
            container.appendChild(rendererMedal.domElement);

            let medal;
            const color = unlocked ? 0xffd700 : 0x333333;

            // Different shapes for different achievements
            if (id.includes('click')) {
                medal = new THREE.Mesh(new THREE.IcosahedronGeometry(1.2, 0), new THREE.MeshStandardMaterial({color, wireframe:!unlocked}));
            } else if (id.includes('rich') || id.includes('billionaire')) {
                medal = new THREE.Mesh(new THREE.OctahedronGeometry(1.2, 0), new THREE.MeshStandardMaterial({color, wireframe:!unlocked}));
            } else {
                medal = new THREE.Mesh(new THREE.TorusKnotGeometry(0.8, 0.3, 64, 8), new THREE.MeshStandardMaterial({color, wireframe:!unlocked}));
            }

            if (unlocked) {
                medal.material.emissive = new THREE.Color(color);
                medal.material.emissiveIntensity = 0.5;
            }
            sceneMedal.add(medal);

            const light = new THREE.PointLight(0xffffff, 2);
            light.position.set(2, 2, 5);
            sceneMedal.add(light);
            sceneMedal.add(new THREE.AmbientLight(0x404040, 1));

            function animateMedal() {
                if (document.getElementById('achievements-overlay').style.display === 'none') {
                    rendererMedal.dispose();
                    return;
                }
                requestAnimationFrame(animateMedal);
                medal.rotation.y += 0.02;
                medal.rotation.x += 0.01;
                rendererMedal.render(sceneMedal, cameraMedal);
            }
            animateMedal();
        }

        function checkAchievements() {
            ACHIEVEMENTS.forEach(ach => {
                if (state.achievements.includes(ach.id)) return;
                let val = 0;
                if (ach.type === 'energy') val = state.energy;
                if (ach.type === 'drones') val = state.drones.length;
                if (ach.type === 'matter') val = state.matter;
                if (ach.type === 'lucky') val = state.profile.lucky ? 1 : 0;
                if (ach.type === 'click') val = state.energy > 0 ? 1 : 0;

                if (val >= ach.goal) {
                    state.achievements.push(ach.id);
                    createToast(`ACHIEVEMENT UNLOCKED: ${ach.title}`);
                    if (ach.reward) {
                        state.inventory.push(ach.reward);
                        createToast(`REWARD ADDED TO CARGO`);
                    }
                    saveGameState();
                }
            });
        }

        let isTMenuOpen = false;
        let tMenuRenderer, tMenuScene, tMenuCamera, tMenuTunnel, tMenuClock;
        let currentTLevel = 0;
        let targetTLevelZ = 80;
        let currentTLevelZ = 80;
        const T_SPACING = 40;

        const LEVEL_DATA = Array.from({ length: 50 }, (_, i) => ({
            name: `ZONE_AX-${(i+1).toString().padStart(2, '0')}`,
            desc: `Strategic point ${i+1}. Recon drones report high-value tech signatures. Heavy automated defense grid active.`,
            diff: i < 15 ? 'STABLE' : (i < 35 ? 'DANGEROUS' : 'CRITICAL'),
            color: i < 15 ? 0x00ffff : (i < 35 ? 0x8800ff : 0xff0055),
            rewards: { xp: (i + 1) * 300, cr: (i + 1) * 120, item: i % 10 === 0 ? "Void Core" : "Scrap" }
        }));

        function toggleLeveling() {
            const overlay = document.getElementById('level-overlay');
            isTMenuOpen = overlay.style.display !== 'flex';
            overlay.style.display = isTMenuOpen ? 'flex' : 'none';

            if (isTMenuOpen) {
                initTMenu3D();
                updateTMenuUI();
                document.getElementById('t-info-panel').style.opacity = '1';
            } else {
                if (tMenuRenderer) {
                    tMenuRenderer.dispose();
                    document.getElementById('t-canvas-container').innerHTML = '';
                    tMenuRenderer = null;
                }
            }
        }

        function initTMenu3D() {
            const container = document.getElementById('t-canvas-container');
            tMenuScene = new THREE.Scene();
            tMenuScene.fog = new THREE.FogExp2(0x020205, 0.01);
            tMenuCamera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 3000);
            tMenuCamera.position.set(0, 0, 80);
            tMenuClock = new THREE.Clock();

            tMenuRenderer = new THREE.WebGLRenderer({ antialias: true });
            tMenuRenderer.setSize(window.innerWidth, window.innerHeight);
            container.appendChild(tMenuRenderer.domElement);

            tMenuTunnel = new THREE.Group();
            tMenuScene.add(tMenuTunnel);

            const mainFrameGeo = new THREE.BoxGeometry(20, 0.5, 2);
            const sideFrameGeo = new THREE.BoxGeometry(0.5, 12, 2);

            LEVEL_DATA.forEach((lvl, i) => {
                const group = new THREE.Group();
                group.position.z = -i * T_SPACING;
                const mat = new THREE.MeshStandardMaterial({ color: lvl.color, metalness: 0.9, roughness: 0.1, emissive: lvl.color, emissiveIntensity: 0.2 });

                const top = new THREE.Mesh(mainFrameGeo, mat); top.position.y = 6;
                const bottom = new THREE.Mesh(mainFrameGeo, mat); bottom.position.y = -6;
                const left = new THREE.Mesh(sideFrameGeo, mat); left.position.x = -10;
                const right = new THREE.Mesh(sideFrameGeo, mat); right.position.x = 10;
                group.add(top, bottom, left, right);

                const ring = new THREE.Mesh(new THREE.TorusGeometry(3, 0.05, 16, 32), mat);
                ring.rotation.x = Math.PI/2;
                group.add(ring);

                tMenuTunnel.add(group);
            });

            tMenuScene.add(new THREE.PointLight(0xffffff, 1, 100));
            tMenuScene.add(new THREE.AmbientLight(0x404040));

            function animateT() {
                if (!isTMenuOpen) return;
                requestAnimationFrame(animateT);
                const time = tMenuClock.getElapsedTime();
                currentTLevelZ += (targetTLevelZ - currentTLevelZ) * 0.06;
                tMenuCamera.position.z = currentTLevelZ;

                tMenuTunnel.children.forEach((group, i) => {
                    const dist = Math.abs(group.position.z - tMenuCamera.position.z + 20);
                    if (i === currentTLevel) {
                        group.scale.setScalar(1 + Math.sin(time * 4) * 0.03);
                    } else {
                        group.scale.setScalar(1);
                    }
                    group.visible = dist < 400;
                });
                tMenuRenderer.render(tMenuScene, tMenuCamera);
            }
            animateT();
        }

        function changeTLevel(dir) {
            currentTLevel = Math.max(0, Math.min(LEVEL_DATA.length - 1, currentTLevel + dir));
            targetTLevelZ = -currentTLevel * T_SPACING + 20;
            updateTMenuUI();
        }

        function updateTMenuUI() {
            const data = LEVEL_DATA[currentTLevel];
            document.getElementById('t-ui-name').innerText = data.name;
            document.getElementById('t-ui-desc').innerText = data.desc;
            document.getElementById('t-ui-diff').innerText = data.diff;
            document.getElementById('t-ui-diff').style.color = '#' + new THREE.Color(data.color).getHexString();
            document.getElementById('t-rew-xp').innerText = `+${data.rewards.xp} XP`;
            document.getElementById('t-rew-cr').innerText = `${data.rewards.cr} NRG`;
            document.getElementById('t-rew-it').innerText = data.rewards.item;
        }

        function startSectorOperation() {
            const data = LEVEL_DATA[currentTLevel];
            if (state.level >= currentTLevel + 1) {
                createToast(`OPERATION STARTED IN ${data.name}`);
                spawnSettlement(currentTLevel);
                toggleLeveling();
            } else {
                createToast(`LEVEL ${currentTLevel + 1} REQUIRED`);
            }
        }

        function addXP(amt) {
            state.xp += amt;
            const xpNext = state.level * 1000;
            if (state.xp >= xpNext) {
                state.xp -= xpNext;
                state.level++;
                state.energy += 5000;
                state.sp++;
                createToast(`LEVEL UP: ${state.level}! REWARDS GRANTED.`);
                if (state.level === 20) createToast("TRADING SYSTEM UNLOCKED [M]");
                saveGameState();
            }
            if (document.getElementById('level-overlay').style.display === 'flex') updateLevelUI();
        }

        let activeTradeId = null;
        let activeTradeUnsubscribe = null;

        function toggleTrading() {
            if (state.level < 20) {
                createToast("TRADING UNLOCKS AT LEVEL 20");
                return;
            }
            const overlay = document.getElementById('trade-overlay');
            const isOpening = overlay.style.display !== 'flex';
            overlay.style.display = isOpening ? 'flex' : 'none';
            if (isOpening) {
                loadTradeBoard();
                document.getElementById('trade-board').style.display = 'block';
                document.getElementById('create-trade-form').style.display = 'none';
                document.getElementById('active-exchange-ui').style.display = 'none';
                document.getElementById('trade-close-btn').style.display = 'block';
            }
        }

        function showCreateTrade() {
            document.getElementById('trade-board').style.display = 'none';
            document.getElementById('create-trade-form').style.display = 'block';
        }

        function hideCreateTrade() {
            document.getElementById('trade-board').style.display = 'block';
            document.getElementById('create-trade-form').style.display = 'none';
        }

        async function submitTradeRequest() {
            const name = document.getElementById('trade-name-input').value.trim();
            const minClicks = parseInt(document.getElementById('trade-clicks-input').value) || 0;
            if (!name) return createToast("ENTER TRADE NAME");

            const user = firebase.auth().currentUser;
            try {
                await db.collection("trades").add({
                    name: name,
                    minClicks: minClicks,
                    offerer: user.uid,
                    offererName: state.profile.name,
                    offererItems: [],
                    receiver: null,
                    receiverName: null,
                    receiverItems: [],
                    status: "open",
                    offererConfirmed: false,
                    receiverConfirmed: false,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp()
                });
                hideCreateTrade();
                createToast("TRADE REQUEST BROADCASTED");
                loadTradeBoard();
            } catch(e) { createToast("TRANSMISSION ERROR"); }
        }

        async function loadTradeBoard() {
            const list = document.getElementById('active-trades-list');
            list.innerHTML = '<div style="color:#0f0">Scanning network...</div>';

            const snapshot = await db.collection("trades")
                .where("status", "==", "open")
                .orderBy("createdAt", "desc")
                .limit(20).get();

            list.innerHTML = '';
            if (snapshot.empty) {
                list.innerHTML = '<div style="color:#555; text-align:center;">No active requests.</div>';
                return;
            }

            snapshot.forEach(doc => {
                const trade = doc.data();
                const div = document.createElement('div');
                div.style.cssText = "background:rgba(0,255,0,0.05); border:1px solid #0f04; padding:15px; margin-bottom:10px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;";

                div.innerHTML = `
                    <div>
                        <b style="color:#0f0">${trade.name}</b><br>
                        <small style="color:#aaa">By: ${trade.offererName}</small>
                    </div>
                    <div style="text-align:right;">
                        <small style="color:#0ff">Req: ${trade.minClicks} Energy</small><br>
                        <button onclick="joinTrade('${doc.id}')" style="margin-top:5px; background:#0f0; color:#000; border:none; padding:5px 15px; cursor:pointer; font-weight:bold;">JOIN</button>
                    </div>
                `;
                list.appendChild(div);
            });
        }

        async function joinTrade(tradeId) {
            const tradeRef = db.collection("trades").doc(tradeId);
            const doc = await tradeRef.get();
            const trade = doc.data();

            if (trade.minClicks > state.energy) {
                return createToast(`REQUIRED: ${trade.minClicks} NRG (Need ${trade.minClicks - state.energy} more)`);
            }

            const user = firebase.auth().currentUser;
            if (trade.offerer !== user.uid) {
                await tradeRef.update({
                    receiver: user.uid,
                    receiverName: state.profile.name,
                    status: "active"
                });
            }

            startExchange(tradeId);
        }

        function startExchange(tradeId) {
            activeTradeId = tradeId;
            document.getElementById('trade-board').style.display = 'none';
            document.getElementById('active-exchange-ui').style.display = 'block';
            document.getElementById('trade-close-btn').style.display = 'none';

            if (activeTradeUnsubscribe) activeTradeUnsubscribe();

            activeTradeUnsubscribe = db.collection("trades").doc(tradeId).onSnapshot(doc => {
                if (!doc.exists) {
                    cancelActiveTrade();
                    return;
                }
                const trade = doc.data();
                renderExchangeUI(trade);

                if (trade.status === "completed") {
                    createToast("EXCHANGE COMPLETED");
                    finishExchange(trade);
                }
            });
        }

        function renderExchangeUI(trade) {
            const user = firebase.auth().currentUser;
            const isOfferer = trade.offerer === user.uid;

            const myItems = isOfferer ? trade.offererItems : trade.receiverItems;
            const partnerItems = isOfferer ? trade.receiverItems : trade.offererItems;

            document.getElementById('my-trade-label').innerText = "YOU (" + state.profile.name + ")";
            document.getElementById('partner-trade-label').innerText = isOfferer ? (trade.receiverName || "WAITING...") : trade.offererName;

            renderSlots('my-trade-slots', myItems, true);
            renderSlots('partner-trade-slots', partnerItems, false);

            const myConfirmed = isOfferer ? trade.offererConfirmed : trade.receiverConfirmed;
            const partnerConfirmed = isOfferer ? trade.receiverConfirmed : trade.offererConfirmed;

            document.getElementById('my-confirm-status').innerText = "Status: " + (myConfirmed ? "CONFIRMED" : "Pending");
            document.getElementById('my-confirm-status').style.color = myConfirmed ? "#0f0" : "#aaa";

            document.getElementById('partner-confirm-status').innerText = "Status: " + (partnerConfirmed ? "CONFIRMED" : "Pending");
            document.getElementById('partner-confirm-status').style.color = partnerConfirmed ? "#0f0" : "#aaa";

            const btn = document.getElementById('trade-confirm-btn');
            btn.innerText = myConfirmed ? "UNCONFIRM" : "CONFIRM";
            btn.style.background = myConfirmed ? "#555" : "#0f0";
        }

        function renderSlots(id, items, canRemove) {
            const grid = document.getElementById(id);
            grid.innerHTML = '';
            items.forEach((name, i) => {
                const div = document.createElement('div');
                div.className = 'inv-item';
                div.innerHTML = `<b style="font-size:0.6rem;">${name}</b>`;
                if (canRemove) {
                    div.style.cursor = 'pointer';
                    div.title = "Click to remove";
                    div.onclick = () => removeItemFromActiveTrade(name);
                }
                grid.appendChild(div);
            });
        }

        async function openTradeItemSelector() {
            const overlay = document.createElement('div');
            overlay.className = 'overlay';
            overlay.style.display = 'flex';
            overlay.style.zIndex = '2000';
            overlay.innerHTML = `
                <div class="menu-window" style="max-width: 400px;">
                    <h3>SELECT ITEM</h3>
                    <div class="inv-grid" id="trade-select-grid"></div>
                    <button onclick="this.parentElement.parentElement.remove()" style="margin-top:20px; width:100%; padding:10px; background:#333; color:#fff; border:none; cursor:pointer;">CANCEL</button>
                </div>
            `;
            document.body.appendChild(overlay);

            const grid = document.getElementById('trade-select-grid');
            state.inventory.forEach((name, i) => {
                const div = document.createElement('div');
                div.className = 'inv-item';
                div.innerHTML = `<b>${name}</b>`;
                div.onclick = async () => {
                    await addItemToActiveTrade(name);
                    overlay.remove();
                };
                grid.appendChild(div);
            });
        }

        async function addItemToActiveTrade(name) {
            const tradeRef = db.collection("trades").doc(activeTradeId);
            const user = firebase.auth().currentUser;
            const doc = await tradeRef.get();
            const trade = doc.data();
            const isOfferer = trade.offerer === user.uid;

            const idx = state.inventory.indexOf(name);
            if (idx > -1) {
                state.inventory.splice(idx, 1);
                updateInventoryUI();

                const update = {};
                if (isOfferer) {
                    update.offererItems = firebase.firestore.FieldValue.arrayUnion(name);
                    update.offererConfirmed = false;
                    update.receiverConfirmed = false;
                } else {
                    update.receiverItems = firebase.firestore.FieldValue.arrayUnion(name);
                    update.offererConfirmed = false;
                    update.receiverConfirmed = false;
                }
                await tradeRef.update(update);
            }
        }

        async function removeItemFromActiveTrade(name) {
            const tradeRef = db.collection("trades").doc(activeTradeId);
            const user = firebase.auth().currentUser;
            const doc = await tradeRef.get();
            const trade = doc.data();
            const isOfferer = trade.offerer === user.uid;

            state.inventory.push(name);
            updateInventoryUI();

            const update = {};
            if (isOfferer) {
                update.offererItems = firebase.firestore.FieldValue.arrayRemove(name);
                update.offererConfirmed = false;
                update.receiverConfirmed = false;
            } else {
                update.receiverItems = firebase.firestore.FieldValue.arrayRemove(name);
                update.offererConfirmed = false;
                update.receiverConfirmed = false;
            }
            await tradeRef.update(update);
        }

        async function confirmActiveTrade() {
            const tradeRef = db.collection("trades").doc(activeTradeId);
            const doc = await tradeRef.get();
            const trade = doc.data();
            const user = firebase.auth().currentUser;
            const isOfferer = trade.offerer === user.uid;

            const update = {};
            if (isOfferer) {
                update.offererConfirmed = !trade.offererConfirmed;
            } else {
                update.receiverConfirmed = !trade.receiverConfirmed;
            }

            await tradeRef.update(update);

            const finalTrade = (await tradeRef.get()).data();
            if (finalTrade.offererConfirmed && finalTrade.receiverConfirmed) {
                await tradeRef.update({ status: "completed" });
            }
        }

        function finishExchange(trade) {
            const user = firebase.auth().currentUser;
            const isOfferer = trade.offerer === user.uid;
            const receivedItems = isOfferer ? trade.receiverItems : trade.offererItems;

            state.inventory.push(...receivedItems);
            updateInventoryUI();
            saveGameState();

            setTimeout(cancelActiveTrade, 2000);
        }

        function cancelActiveTrade() {
            if (activeTradeUnsubscribe) activeTradeUnsubscribe();
            activeTradeUnsubscribe = null;
            activeTradeId = null;

            document.getElementById('active-exchange-ui').style.display = 'none';
            document.getElementById('trade-board').style.display = 'block';
            document.getElementById('trade-close-btn').style.display = 'block';
            loadTradeBoard();
        }

        async function askAI() {
            const input = document.getElementById('ai-input');
            const box = document.getElementById('ai-chat-box');
            const query = input.value.trim();
            if (!query) return;

            const userMsg = document.createElement('div');
            userMsg.style.margin = "10px 0";
            userMsg.innerHTML = `<b style="color:#fff">YOU:</b> ${query}`;
            box.appendChild(userMsg);
            input.value = '';

            try {
                const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + GROQ_API_KEY
                    },
                    body: JSON.stringify({
                        model: "llama3-8b-8192",
                        messages: [
                            { role: "system", content: "You are KRONOS, the high-level diagnostic AI of 'Acis System'. \nYour persona: Professional, slightly clinical, extremely helpful but strictly mission-oriented.\nGame Context:\n- NRG (Energy): Harvested from Core or Drones. Current: " + state.energy + ".\n- Drones: Basic, Mega, Fragile, Tank, Scavenger, Turbo, VIP. VIP drones have 10M HP.\n- Combat: Select drones to attack Settlements (spawned > 600m away).\n- Trading (M): Real-time Firestore exchange board. Requires Level 20.\n- Ascension: Reset for Antimatter multipliers.\n- VIP Status: $1B NRG. Exclusive badge and drones.\n- Stock Market: Invest NRG in corporations to bypass storage limits." },
                            { role: "user", content: query }
                        ]
                    })
                });

                const data = await response.json();
                if (!data.choices) throw new Error("API ERROR");
                const reply = data.choices[0].message.content;

                const aiMsg = document.createElement('div');
                aiMsg.style.margin = "10px 0";
                aiMsg.innerHTML = `<b style="color:#0ff">KRONOS:</b> ${reply}`;
                box.appendChild(aiMsg);
                box.scrollTop = box.scrollHeight;

                // 50% Voice Chance
                if (Math.random() < 0.5) {
                    const utterance = new SpeechSynthesisUtterance(reply);
                    utterance.rate = 1.1;
                    utterance.pitch = 0.8;
                    window.speechSynthesis.speak(utterance);
                    createToast("VOICE TRANSMISSION ACTIVE");
                }
            } catch (e) {
                const errMsg = document.createElement('div');
                errMsg.style.color = "#f00";
                errMsg.innerText = "KRONOS: Link failure. Retry requested.";
                box.appendChild(errMsg);
            }
        }

        function toggleMenu(id) {
            const el = document.getElementById(id + '-overlay');
            if (el) el.style.display = el.style.display === 'flex' ? 'none' : 'flex';
        }

        function toggleInfoPanel() {
            const panel = document.getElementById('info-panel');
            panel.classList.toggle('active');
        }

        function updateInventoryUI() {
            const grid = document.getElementById('inv-grid-q');
            if (!grid) return;
            grid.innerHTML = '';

            const maxSlots = 16;
            const itemsToShow = state.inventory.slice(0, maxSlots);

            document.getElementById('inv-header-q').innerText = `CARGO_HOLD [${state.inventory.length}/16]`;

            for (let i = 0; i < maxSlots; i++) {
                const slot = document.createElement('div');
                slot.className = 'slot';

                if (i < itemsToShow.length) {
                    const itemName = itemsToShow[i];
                    const itemData = ITEMS[itemName] || { icon: '?', color: '#fff', desc: '???' };

                    let rarityColor = "#fff";
                    if(itemData.rarity === "Rare") rarityColor = "#0ff";
                    if(itemData.rarity === "Epic") rarityColor = "#f0f";
                    if(itemData.rarity === "Legendary") rarityColor = "#ffd700";

                    slot.innerHTML = `<span style="color:${rarityColor}; font-size: 1.5rem;">${itemData.icon || '⬢'}</span>`;
                    slot.onmouseover = () => showItemDetail(itemName, itemData);
                    slot.onmouseleave = () => hideItemDetail();
                    slot.onclick = () => useItem(i);
                } else {
                    slot.style.opacity = "0.2";
                    slot.innerText = "·";
                }
                grid.appendChild(slot);
            }
            updateExpeditionsUI();
        }

        function showItemDetail(name, data) {
            const tooltip = document.getElementById('item-desc-q');
            document.getElementById('it-name-q').innerText = name;
            document.getElementById('it-text-q').innerText = data.desc || data.text || "No data.";
            document.getElementById('it-type-q').style.color = data.color || "#0ff";
            tooltip.classList.add('active');
            tooltip.style.opacity = '1';
            if (qMenuCore) qMenuCore.material.color.set(data.color || "#00f2ff");
        }

        function hideItemDetail() {
            const tooltip = document.getElementById('item-desc-q');
            tooltip.classList.remove('active');
            tooltip.style.opacity = '0';
            if (qMenuCore) qMenuCore.material.color.set(0x00f2ff);
        }

        function toggleDroneCombat(i) {
            const d = state.drones[i];
            d.inCombat = !d.inCombat;
            createToast(d.inCombat ? "DRONE TARGETING ENGAGED" : "DRONE HARVESTING ONLY");
            updateInventoryUI();
        }

        function returnDrone(i) {
            const d = state.drones[i];
            const name = d.type.charAt(0).toUpperCase() + d.type.slice(1) + " Drone";
            state.inventory.push(name);
            scene.remove(d.mesh);
            scene.remove(d.laser);
            state.drones.splice(i, 1);
            createToast("DRONE RETURNED TO CARGO");
            updateInventoryUI();
            saveGameState();
        }

        function showBattleReport(deadDrones, nrgGained) {
            const stats = document.getElementById('battle-stats');
            stats.innerHTML = `
                <div style="color: #0f0; margin-bottom: 10px;">SUCCESSFUL MISSION</div>
                <div style="display: flex; justify-content: space-between;">
                    <span>ENERGY RECOVERED:</span>
                    <span style="color: #0f0;">+${nrgGained.toLocaleString()} NRG</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                    <span>UNITS LOST:</span>
                    <span style="color: #f00;">${deadDrones.length}</span>
                </div>
                <ul style="color: #aaa; font-size: 0.6rem;">
                    ${deadDrones.map(d => `<li>${d.type.toUpperCase()} DRONE</li>`).join('')}
                </ul>
                <div style="margin-top: 10px;">REMAINING FLEET STATUS:</div>
                <div style="max-height: 150px; overflow-y: auto; font-size: 0.6rem; color: #888;">
                    ${state.drones.map(d => `<div>${d.type.toUpperCase()}: ${Math.floor(d.hp)} HP</div>`).join('')}
                </div>
            `;
            const overlay = document.getElementById('battle-overlay');
            overlay.style.display = 'flex';
        }

        function startExpedition() {
            if (state.energy >= 1000) {
                state.energy -= 1000;
                const endTime = Date.now() + 300000; // 5 minutes
                state.expeditions.push({ end: endTime, claimed: false });
                createToast("MISSION STARTED");
                updateExpeditionsUI();
                updateUI();
            } else {
                createToast("NOT ENOUGH ENERGY");
            }
        }

        function updateExpeditionsUI() {
            const list = document.getElementById('exp-list');
            if (!list) return;
            list.innerHTML = '';
            const now = Date.now();
            state.expeditions.forEach((ex, i) => {
                if (ex.claimed) return;
                const div = document.createElement('div');
                div.style.cssText = "background:rgba(0,255,255,0.05); border:1px solid #0ff4; padding:15px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;";
                const timeLeft = Math.max(0, Math.ceil((ex.end - now) / 1000));

                if (timeLeft > 0) {
                    div.innerHTML = `<span>SCOUTING SECTOR ${i+1}...</span><span style="color:#0ff">${Math.floor(timeLeft/60)}:${(timeLeft%60).toString().padStart(2,'0')}</span>`;
                } else {
                    div.innerHTML = `<span>MISSION COMPLETE!</span><button onclick="claimExpedition(${i})" style="background:#0ff; border:none; padding:5px 15px; cursor:pointer; font-family:'Orbitron'; font-weight:bold;">CLAIM</button>`;
                }
                list.appendChild(div);
            });
        }

        function claimExpedition(idx) {
            state.expeditions[idx].claimed = true;
            const rewards = ["Dark Matter", "Cyber Chip", "Crystal", "Ancient Tech", "Energy Sphere"];
            const reward = rewards[Math.floor(Math.random()*rewards.length)];
            state.inventory.push(reward);
            createToast(`RECOVERED: ${reward}`);
            updateInventoryUI();
        }

        let lastEnergy = 0;
        function flushCoolant() {
            if (state.energy >= 500 && state.heat > 0) {
                state.energy -= 500;
                state.heat = 0;
                createToast("COOLANT FLUSHED");
                updateUI();
            } else if (state.heat === 0) {
                createToast("CORE TEMPERATURE STABLE");
            } else {
                createToast("NOT ENOUGH ENERGY");
            }
        }

        let calTimeout = null;
        function calibratePulse() {
            const btn = document.getElementById('cal-btn');
            btn.style.transform = "scale(0.9)";
            setTimeout(() => btn.style.transform = "scale(1)", 100);

            state.multiplier = Math.min(5, state.multiplier + 0.1);
            if (calTimeout) clearTimeout(calTimeout);
            calTimeout = setTimeout(() => {
                const interval = setInterval(() => {
                    state.multiplier -= 0.05;
                    if (state.multiplier <= 1) {
                        state.multiplier = 1;
                        clearInterval(interval);
                    }
                    updateUI();
                }, 100);
            }, 2000);
            updateUI();
        }

        function synthesizeMatter() {
            if (state.energy >= 10000) {
                state.energy -= 10000;
                state.matter += 1;
                updateUI();
                createToast("MATTER SYNTHESIZED");
            } else {
                createToast("NOT ENOUGH ENERGY");
            }
        }

        function checkContracts() {
            state.contracts.forEach(c => {
                if (c.done) return;
                let progress = 0;
                if (c.type === "energy") progress = state.energy;
                if (c.type === "drones") progress = state.drones.length;
                if (progress >= c.goal) {
                    c.done = true;
                    state.energy += c.reward;
                    createToast(`CONTRACT COMPLETE: ${c.title} (+${c.reward} NRG)`);
                }
            });
            updateContractsUI();
        }

        function updateContractsUI() {
            const list = document.getElementById('contract-list');
            if (!list) return;
            list.innerHTML = '';
            state.contracts.forEach(c => {
                const div = document.createElement('div');
                div.style.cssText = `background:rgba(0,255,255,0.05); border:1px solid ${c.done ? '#0f04' : '#0ff4'}; padding:15px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;`;
                div.innerHTML = `<div><b style="color:${c.done ? '#0f0' : '#0ff'}">${c.title}</b><br><small style="color:#aaa">${c.desc}</small></div>
                                 <span style="color:${c.done ? '#0f0' : '#aaa'}">${c.done ? 'COMPLETED' : 'IN PROGRESS'}</span>`;
                list.appendChild(div);
            });
        }

        let isPaused = false;
        function setGameSpeed(s) {
            state.playSpeed = s;
            createToast(`TIME DILATION: x${s}`);
            // Visual feedback for selected speed
            document.querySelectorAll('#speed-controls button').forEach(b => {
                b.style.borderColor = b.innerText.includes(s) ? "#0ff" : "#0ff4";
            });
        }
        function togglePause() {
            isPaused = !isPaused;
            document.getElementById('pause-btn').innerText = isPaused ? 'RESUME' : 'STOP';
            document.getElementById('pause-btn').style.background = isPaused ? '#0f0' : '#f00';
            createToast(isPaused ? "CORE SUSPENDED" : "CORE RESUMED");
        }

        let lastUIUpdate = 0;
        function updateUI(force = false) {
            const now = Date.now();
            if (!force && now - lastUIUpdate < 100) return; // Limit to 10FPS for UI
            lastUIUpdate = now;

            checkContracts();
            checkAchievements();
            if (state.isVIP) {
                document.getElementById('vip-badge').style.display = 'block';
                document.getElementById('profile-name-span').style.color = '#ffd700';
                document.getElementById('profile-name-span').classList.add('vip-glow');
            } else {
                document.getElementById('profile-name-span').style.color = state.nickColor || '#ffffff';
            }
            document.getElementById('drone-count').innerText = state.drones.length;
            if (document.getElementById('matter-val')) {
                document.getElementById('matter-val').innerText = state.matter;
            }
            if (document.getElementById('antimatter-val')) {
                document.getElementById('antimatter-val').innerText = state.antimatter;
            }
            const energyEl = document.getElementById('energy-display');
            if (state.energy > lastEnergy) {
                energyEl.classList.add('pulse-active');
                setTimeout(() => energyEl.classList.remove('pulse-active'), 150);
            }
            lastEnergy = state.energy;

            energyEl.innerText = Math.floor(state.energy).toLocaleString() + " NRG";
            document.getElementById('storage-fill').style.width = Math.min(100, (state.energy / state.storageMax * 100)) + "%";
            document.getElementById('storage-text').innerText = `${Math.floor(state.energy)} / ${state.storageMax}`;

            // Heat UI
            document.getElementById('heat-fill').style.width = state.heat + "%";
            if (state.heat > 80) document.getElementById('warning-label').innerText = "CORE OVERHEAT!";
            else if (state.energy > state.storageMax) document.getElementById('warning-label').innerText = "CRITICAL OVERLOAD";

            // Calibration UI
            document.getElementById('mult-val').innerText = "x" + state.multiplier.toFixed(1);
            document.getElementById('cal-btn').style.background = state.multiplier > 4 ? "#f0f" : "#0ff";

            // Jetpack UI
            document.getElementById('fuel-val').innerText = Math.max(0, Math.ceil(state.jetpack.fuel));
            document.getElementById('fuel-fill').style.width = (state.jetpack.fuel / state.jetpack.maxFuel * 100) + "%";
            document.getElementById('fuel-fill').style.background = state.jetpack.cooldown > 0 ? "#555" : "#f0f";
            document.getElementById('cost-click').innerText = "Цена: " + state.costs.click;
            document.getElementById('cost-drone').innerText = "Цена: " + state.costs.drone;
            document.getElementById('cost-storage').innerText = "Цена: " + state.costs.storage;
            document.getElementById('cost-matter').innerText = "Цена: " + state.costs.matter;
            document.getElementById('cost-plating').innerText = "Цена: " + state.costs.plating;
        }

        let wires = [];
        function createInitialWire() {
            const curve = new THREE.CubicBezierCurve3(
                new THREE.Vector3(-15, 5, 0),
                new THREE.Vector3(-5, 12, 0),
                new THREE.Vector3(5, 12, 0),
                new THREE.Vector3(15, 12, 0)
            );
            const geo = new THREE.TubeGeometry(curve, 20, 0.15, 8, false);
            const mat = new THREE.MeshStandardMaterial({ color: 0x00ffff, emissive: 0x00ffff, emissiveIntensity: 1 });
            const wire = new THREE.Mesh(geo, mat);
            scene.add(wire);
            wires.push(wire);
        }

        async function ascend() {
            if (state.energy >= 1000000) {
                const gain = Math.floor(state.energy / 1000000);
                state.antimatter += gain;
                state.energy = 0;
                state.xp = 0;
                state.level = 1;
                state.matter = 0;
                state.storageMax = 400;
                state.clickPower = 5;
                state.costs = { click: 50, drone: 150, storage: 250, matter: 1000, plating: 500 };
                state.inventory = [];
                state.drones = [];
                state.storageModules = [];
                createToast("ASCENSION COMPLETE: ANTIMATTER ACQUIRED");
                updateUI();
                await saveGameState();
                location.reload();
            } else {
                createToast("NOT ENOUGH ENERGY FOR ASCENSION");
            }
        }

        function spawnSettlement(level = null) {
            const angle = Math.random() * Math.PI * 2;
            const dist = 600 + Math.random() * 2000; // 600m to 2600m away
            const x = Math.cos(angle) * dist;
            const z = Math.sin(angle) * dist;

            const group = new THREE.Group();
            group.position.set(x, 0, z);

            const baseColor = level !== null ? LEVEL_DATA[level].color : 0x333333;
            const base = new THREE.Mesh(new THREE.CylinderGeometry(5, 6, 2, 6), new THREE.MeshStandardMaterial({color: 0x333333, roughness: 0.8, emissive: baseColor, emissiveIntensity: 0.2}));
            group.add(base);

            const tower = new THREE.Mesh(new THREE.BoxGeometry(2, 8, 2), new THREE.MeshStandardMaterial({color: 0x222222, emissive: 0xff0000, emissiveIntensity: 0.5}));
            tower.position.y = 4;
            group.add(tower);

            scene.add(group);
            const settlement = {
                group,
                hp: level !== null ? (level + 1) * 1000 : 500,
                id: Math.random().toString(36).substr(2,5),
                reward: level !== null ? LEVEL_DATA[level].rewards : null,
                level: level
            };
            settlements.push(settlement);

            createToast("NEW AI SETTLEMENT DETECTED!");
            showSettlementArrow(group.position);

            setTimeout(() => {
                if (group.parent) scene.remove(group);
                settlements = settlements.filter(s => s.id !== settlement.id);
            }, 300000); // 5 mins
        }

        function showSettlementArrow(pos) {
            const arrow = document.createElement('div');
            arrow.id = "target-arrow";
            arrow.style.cssText = "position:absolute; top:50%; left:50%; width:0; height:0; border-left:20px solid transparent; border-right:20px solid transparent; border-bottom:30px solid #f00; transform-origin: center 50px; z-index:5000;";
            document.body.appendChild(arrow);

            const timer = setInterval(() => {
                if (!camera) return;
                const screenPos = pos.clone().project(camera);
                const angle = Math.atan2(screenPos.y, screenPos.x);
                arrow.style.transform = `translate(-50%, -50%) rotate(${angle + Math.PI/2}rad) translateY(-150px)`;
            }, 16);

            setTimeout(() => {
                clearInterval(timer);
                arrow.remove();
            }, 5000);
        }

        function initStockMarket() {
            setInterval(() => {
                corporations.forEach(c => {
                    const change = 1 + (Math.random() - 0.5) * c.volatility;
                    c.price *= change;
                    if (c.price < 10) c.price = 10;
                    c.history.push(c.price);
                    if (c.history.length > 20) c.history.shift();
                });
                updateStockUI();
            }, 30000);

            const termGeo = new THREE.BoxGeometry(5, 8, 1);
            const termMat = new THREE.MeshStandardMaterial({color: 0x222222, emissive: 0x00ffff, emissiveIntensity: 0.1});
            const terminal = new THREE.Mesh(termGeo, termMat);
            terminal.position.set(0, 4, -80);
            terminal.name = "STOCK_TERMINAL";
            scene.add(terminal);

            const screen = new THREE.Mesh(new THREE.PlaneGeometry(4.5, 6), new THREE.MeshBasicMaterial({color: 0x001111}));
            screen.position.z = 0.51;
            terminal.add(screen);
        }

        function renderStockGraph() {
            const container = document.getElementById('stock-graph-container');
            if (!container || container.clientWidth === 0) return;
            container.innerHTML = '';
            const canvas = document.createElement('canvas');
            canvas.width = container.clientWidth;
            canvas.height = container.clientHeight;
            container.appendChild(canvas);
            const ctx = canvas.getContext('2d');
            corporations.forEach(c => {
                ctx.beginPath();
                ctx.strokeStyle = '#' + new THREE.Color(c.color).getHexString();
                ctx.lineWidth = 2;
                const step = canvas.width / 20;
                const maxHistory = 20;
                const history = c.history;
                const maxPrice = 1000;
                history.forEach((p, i) => {
                    const x = i * step;
                    const y = canvas.height - (p / maxPrice * canvas.height);
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                });
                ctx.stroke();
            });
        }

        function updateStockUI() {
            const list = document.getElementById('stock-list');
            if (!list) return;
            list.innerHTML = '';
            renderStockGraph();
            corporations.forEach(c => {
                const div = document.createElement('div');
                div.className = 'card';
                div.style.borderColor = '#' + new THREE.Color(c.color).getHexString();
                const trend = c.history.length > 1 && c.history[c.history.length-1] >= c.history[c.history.length-2] ? 'UP' : 'DOWN';
                div.innerHTML = `
                    <b style="color:#${new THREE.Color(c.color).getHexString()}">${c.name}</b><br>
                    <small>Price: ${Math.floor(c.price)} NRG</small><br>
                    <small style="color:${trend === 'UP' ? '#0f0' : '#f00'}">Trend: ${trend}</small><br>
                    <small style="color:#ffd700">Held: ${stockPortfolio[c.id] || 0}</small>
                    <div style="display:flex; gap:5px; margin-top:10px;">
                        <button onclick="buyStock('${c.id}')" style="font-size:0.6rem; background:#0f0; color:#000;">BUY</button>
                        <button onclick="sellStock('${c.id}')" style="font-size:0.6rem; background:#444; color:#fff;">SELL</button>
                    </div>
                `;
                list.appendChild(div);
            });
            document.getElementById('portfolio-val').innerText = Object.values(stockPortfolio).reduce((a,b) => a+b, 0);
        }

        function buyStock(id) {
            const corp = corporations.find(c => c.id === id);
            if (state.energy >= corp.price) {
                state.energy -= corp.price;
                stockPortfolio[id] = (stockPortfolio[id] || 0) + 1;
                createToast(`PURCHASED ${corp.name}`);
                updateStockUI();
                updateUI(true);
            } else { createToast("NOT ENOUGH ENERGY"); }
        }

        function sellStock(id) {
            if (stockPortfolio[id] > 0) {
                const corp = corporations.find(c => c.id === id);
                state.energy += corp.price;
                stockPortfolio[id]--;
                createToast(`SOLD ${corp.name}`);
                updateStockUI();
                updateUI(true);
            } else { createToast("NO SHARES TO SELL"); }
        }

        function startSystems() {
            createInitialWire();
            initStockMarket();
            setInterval(() => { if (!traderDrone) spawnTrader(); }, 3600000); // Once per hour
            setInterval(() => { if (Math.random() < 0.2) spawnSettlement(); }, 60000);
            // Passive Income & Liquid Physics
            setInterval(() => {
                const baseIncome = state.drones.length * 2.5 + 0.1;
                let weatherMult = state.weather.type === 'magnetic_storm' ? 0.5 : 1;
                let antiMult = Math.pow(2, state.antimatter);
                const income = baseIncome * state.multiplier * weatherMult * antiMult * (state.heat > 90 ? 0.1 : 1);
                state.energy += income;
                addXP(income * 0.01);

                // Random drone drop from passive drones
                if (Math.random() < 0.00005 * state.drones.length) {
                    const types = ['fragile', 'tank', 'scavenger', 'turbo'];
                    const type = types[Math.floor(Math.random()*types.length)];
                    state.inventory.push(type.charAt(0).toUpperCase() + type.slice(1) + " Drone");
                    createToast("DRONE RECOVERED BY FLEET!");
                    updateInventoryUI();
                }

                state.heat = Math.min(100, state.heat + (income * 0.05));
                if (state.heat > 0) state.heat = Math.max(0, state.heat - 0.02); // Passive cooling

                let remaining = state.energy;
                const mainCap = 400;

                // Main Tank Filling
                const mainFill = Math.min(remaining / mainCap, 1);
                mainTankLiquid.scale.y = Math.max(0.01, mainFill);

                // Bubbles/Sparks effect when full
                if(mainFill >= 1) {
                    particles.visible = true;
                    particles.position.set(15, 12, 0);
                } else {
                    particles.visible = false;
                }

                remaining -= mainCap;

                // Storage Modules Filling
                state.storageModules.forEach(m => {
                    if(remaining > 0) {
                        const mFill = Math.min(remaining / 5000, 1);
                        m.liq.scale.y = Math.max(0.01, mFill);
                        remaining -= 5000;
                    } else {
                        m.liq.scale.y = 0.01;
                    }
                });

                // Overload Logic
                if(state.energy > state.storageMax) {
                    document.getElementById('warning-label').style.display = 'block';
                    state.energy -= (state.energy - state.storageMax) * 0.02; // Leakage
                } else {
                    document.getElementById('warning-label').style.display = 'none';
                }

                updateUI();
            }, 50);

            // Market Fluctuations
            setInterval(() => {
                for(let k in state.market) {
                    state.market[k] = Math.round(state.market[k] * (0.8 + Math.random() * 0.5));
                    if(state.market[k] < 10) state.market[k] = 10;
                }
                document.getElementById('market-ticker').innerText = `Scrap: $${state.market.Scrap} | Crystal: $${state.market.Crystal} | Matter: $${state.market["Dark Matter"]}`;
            }, 8000);
        }

        function updateWeather(delta) {
            state.weather.timer -= delta;
            if (state.weather.timer <= 0) {
                const types = ['clear', 'magnetic_storm', 'solar_flare'];
                state.weather.type = types[Math.floor(Math.random() * types.length)];
                state.weather.timer = 60 + Math.random() * 120; // 1-3 minutes

                // Visuals
                const amb = scene.getObjectByName("AMBIENT");
                if (state.weather.type === 'magnetic_storm') {
                    scene.fog.color.set(0x440088);
                    scene.background.set(0x110022);
                    if(amb) amb.color.set(0x8800ff);
                    createToast("MAGNETIC STORM: PRODUCTION -50%");
                } else if (state.weather.type === 'solar_flare') {
                    scene.fog.color.set(0xffaa00);
                    scene.background.set(0x221100);
                    if(amb) amb.color.set(0xffcc00);
                    createToast("SOLAR FLARE: CLICK POWER x10");
                } else {
                    scene.fog.color.set(0x00050a);
                    scene.background.set(0x00050a);
                    if(amb) amb.color.set(0x4040ff);
                    createToast("WEATHER CLEAR");
                }
            }
        }

        let frameCount = 0;
        function updateMovement(delta) {
            const altitudeScale = Math.max(1, camera.position.y / 15);
            let moveSpeed = (state.turboActive ? 1.2 : 0.6) * altitudeScale;

            if (keys['AltLeft'] || keys['AltRight']) moveSpeed *= 2; // Sprint

            const move = new THREE.Vector3();

            const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(camera.quaternion);
            forward.y = 0; forward.normalize();
            const right = new THREE.Vector3(1, 0, 0).applyQuaternion(camera.quaternion);
            right.y = 0; right.normalize();

            if(keys['KeyW']) move.add(forward.multiplyScalar(moveSpeed));
            if(keys['KeyS']) move.add(forward.multiplyScalar(-moveSpeed));
            if(keys['KeyA']) move.add(right.multiplyScalar(-moveSpeed));
            if(keys['KeyD']) move.add(right.multiplyScalar(moveSpeed));

            if (state.jetpack.active) {
                state.jetpack.fuel -= delta;
                if (keys['Space']) move.y += moveSpeed;
                if (keys['ControlLeft']) move.y -= moveSpeed;

                if (state.jetpack.fuel <= 0) {
                    state.jetpack.active = false;
                    state.jetpack.fuel = 0;
                    state.jetpack.cooldown = 30;
                    createToast("JETPACK EMPTY - RECHARGING");
                }
            } else {
                if (state.jetpack.cooldown > 0) {
                    state.jetpack.cooldown -= delta;
                    if (state.jetpack.cooldown <= 0) {
                        state.jetpack.fuel = state.jetpack.maxFuel;
                        createToast("JETPACK READY");
                    }
                } else if (state.jetpack.fuel < state.jetpack.maxFuel) {
                    state.jetpack.fuel = state.jetpack.maxFuel;
                }

                if (!document.pointerLockElement) {
                     if(keys['Space']) move.y += moveSpeed;
                     if(keys['ShiftLeft'] || keys['ControlLeft']) move.y -= moveSpeed;
                }
            }

            camera.position.add(move);

            const limit = 10000;
            camera.position.x = THREE.MathUtils.clamp(camera.position.x, -limit, limit);
            camera.position.z = THREE.MathUtils.clamp(camera.position.z, -limit, limit);
            camera.position.y = THREE.MathUtils.clamp(camera.position.y, 1, 500);

            if (state.turboActive) {
                camera.position.x += (Math.random() - 0.5) * 0.2;
                camera.position.y += (Math.random() - 0.5) * 0.2;
            }
        }

        function animate() {
            requestAnimationFrame(animate);
            frameCount++;
            if (isPaused) {
                // Allow movement even when paused
                updateMovement(clock.getDelta());
                renderer.render(scene, camera);
                return;
            }
            if (activeDrone && frameCount % 2 === 0) updateDroneMenuPos();
            const delta = clock.getDelta() * state.playSpeed;
            const time = clock.getElapsedTime();

            if (frameCount % 60 === 0) updateWeather(delta);

            if (traderDrone) {
                traderDrone.timer += delta;
                traderDrone.mesh.position.y = 15 + Math.sin(traderDrone.timer) * 5;
                traderDrone.mesh.rotation.y += 0.02;
                if (traderDrone.timer > 300) {
                    scene.remove(traderDrone.mesh);
                    traderDrone = null;
                }
            }

            // Camera Controls
            if(!isSkillMode) {
                updateMovement(delta);
            }

            // Core Animation & Morphing (BPM Sync: 120 BPM = 2 beats per second)
            core.rotation.y += state.turboActive ? 0.05 : 0.005;
            core.rotation.z += 0.002;
            core.children[0].rotation.y -= 0.01; // Outer ring reverse

            const bpm = 120;
            const beat = (time * (bpm / 60)) % 1;
            const beatFactor = Math.pow(1 - beat, 4); // Sharp pulse

            const energyFactor = state.energy / state.storageMax;
            const targetScale = 1 + beatFactor * 0.2 + energyFactor * 0.5;
            core.scale.lerp(new THREE.Vector3(targetScale, targetScale, targetScale), 0.2);
            core.children[0].material.emissiveIntensity = 0.5 + Math.sin(time*2) * 0.3 + energyFactor;

            // Blackout & Lighting Logic
            const amb = scene.getObjectByName("AMBIENT");
            const mainL = scene.getObjectByName("MAIN_LIGHT");
            const emerL = scene.getObjectByName("EMERGENCY_LIGHT");

            if (state.energy < state.storageMax * 0.1) {
                amb.intensity = 0.05;
                mainL.intensity = 0.2;
                emerL.intensity = 1 + Math.sin(time * 10) * 0.5; // Pulsing Red
            } else {
                amb.intensity = 0.2;
                mainL.intensity = 2;
                emerL.intensity = 0;
            }

            // Overload Visuals (Sparks)
            if (state.energy > state.storageMax) {
                if (Math.random() > 0.8) {
                    const spark = new THREE.Mesh(new THREE.SphereGeometry(0.1), new THREE.MeshBasicMaterial({color: 0xffffff}));
                    spark.position.set(15 + (Math.random()-0.5)*5, 12, (Math.random()-0.5)*5);
                    scene.add(spark);
                    setTimeout(() => scene.remove(spark), 100);
                }
            }

            // Cables Glowing
            state.storageModules.forEach(m => {
                if(m.cable) {
                    m.cable.material.emissiveIntensity = 0.5 + Math.sin(time * 3) * 0.2 + (state.energy / state.storageMax);
                }
            });

            // Drones Logic
            for (let i = state.drones.length - 1; i >= 0; i--) {
                const d = state.drones[i];
                d.timer += delta * d.speed;

                // Movement
                d.mesh.position.y = 8 + Math.sin(d.timer * 2) * 3;
                d.mesh.position.x = Math.cos(d.timer) * 20 - 15;
                d.mesh.position.z = Math.sin(d.timer) * 15;

                // Animation
                d.ring1.rotation.x += 0.05;
                d.ring2.rotation.y += 0.03;
                d.light.intensity = 1 + Math.sin(time * 5) * 0.5;

                // Combat: Targeting Settlements
                let target = null;
                let minDist = Infinity;
                if (d.inCombat) {
                    settlements.forEach(s => {
                        const dist = d.mesh.position.distanceTo(s.group.position);
                        if (dist < d.range && dist < minDist) {
                            minDist = dist;
                            target = s;
                        }
                    });
                }

                if (target && Math.sin(d.timer * 10) > 0.6) {
                    d.laser.material.opacity = 1;
                    d.laser.material.color.set(0x00ffff);
                    d.laser.geometry.setFromPoints([d.mesh.position, target.group.position]);

                    target.hp -= 0.5 * d.multiplier * delta * 60;
                    if (target.hp <= 0) {
                        if (typeof createExplosion === 'function') createExplosion(target.group.position);
                        scene.remove(target.group);
                        settlements.splice(settlements.indexOf(target), 1);

                        let gain = 5000 + Math.floor(Math.random() * 10000);
                        if (target.reward) {
                            gain = target.reward.cr;
                            addXP(target.reward.xp);
                            state.inventory.push(target.reward.item);
                        }

                        state.energy += gain;
                        showBattleReport([], gain);
                        saveGameState();
                    }
                } else if (Math.sin(d.timer * 8) > 0.5) {
                    // Normal Harvesting
                    d.laser.material.opacity = 0.5;
                    d.laser.material.color.set(0xff00ff);
                    d.laser.geometry.setFromPoints([d.mesh.position, core.position]);
                } else {
                    d.laser.material.opacity = 0;
                }

                // AI Retaliation
                settlements.forEach(s => {
                    if (s.group.position.distanceTo(d.mesh.position) < 40 && Math.random() < 0.01) {
                        // Enemy fires at drone
                        const enemyLaserGeo = new THREE.BufferGeometry().setFromPoints([s.group.position, d.mesh.position]);
                        const enemyLaser = new THREE.Line(enemyLaserGeo, new THREE.LineBasicMaterial({color: 0xff0000}));
                        scene.add(enemyLaser);
                        setTimeout(() => scene.remove(enemyLaser), 100);

                        if (d.type !== 'vip') {
                            d.hp -= 10;
                            if (d.hp <= 0) {
                                if (typeof createExplosion === 'function') createExplosion(d.mesh.position);
                                scene.remove(d.mesh);
                                scene.remove(d.laser);
                                state.drones.splice(i, 1);
                                createToast("DRONE DESTROYED!");
                            }
                        }
                    }
                });
            }

            // Particles update
            if(particles.visible) {
                const pos = particles.geometry.attributes.position.array;
                for(let i=0; i<pos.length; i+=3) {
                    pos[i+1] += 0.1;
                    if(pos[i+1] > 5) pos[i+1] = 0;
                }
                particles.geometry.attributes.position.needsUpdate = true;
            }

            // Skill Tree animations & Raycast Feedback
            if(isSkillMode) {
                raycaster.setFromCamera(mouse, camera);
                const skillHits = raycaster.intersectObjects(skillGroup.children, true);

                skillGroup.children.forEach(c => {
                    if(c.userData.name) {
                        c.rotation.y += 0.02;
                        c.rotation.z += 0.01;
                        let s = 1 + Math.sin(time*3) * 0.08;

                        // Pulse effect for active nodes
                        if (c.userData.active) {
                            s += Math.sin(time * 10) * 0.1;
                        }

                        // Hover effect
                        if (skillHits.length > 0) {
                            let h = skillHits[0].object;
                            while(h && h !== c) h = h.parent;
                            if (h === c) {
                                s *= 1.5;
                                if (frameCount % 10 === 0) createToast(c.userData.name);
                            }
                        }
                        c.scale.lerp(new THREE.Vector3(s, s, s), 0.1);
                    }
                });
            }

            renderer.render(scene, camera);
        }

        init();
        window.oncontextmenu = (e) => {
            e.preventDefault();
            if (isTMenuOpen) {
                const panel = document.getElementById('t-info-panel');
                panel.style.opacity = panel.style.opacity === '0' ? '1' : '0';
            }
        };
