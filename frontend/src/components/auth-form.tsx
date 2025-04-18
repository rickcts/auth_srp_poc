import React, { useState } from 'react';
import axios from 'axios';
import { SRP, SrpClient } from 'fast-srp-hap';
import { Buffer } from 'buffer';
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, EyeOff } from 'lucide-react';
import logo from '@/assets/logo.jpg';

const srpParams: typeof SRP.params["hap"] = {
    ...SRP.params[4096],
    hash: 'sha512',
}

const API_BASE_URL = "http://localhost:3000/"; // Make sure your backend server is running here

type AuthMode = 'login' | 'register';

interface AuthFormProps extends Omit<React.ComponentProps<"div">, 'onSubmit'> {
    initialMode?: AuthMode;
}

interface MessageState {
    type: 'error' | 'success' | null;
    text: string;
}

export function AuthForm({
    className,
    initialMode = 'login',
    ...props
}: AuthFormProps) {
    const [mode, setMode] = useState<AuthMode>(initialMode);
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [identity, setIdentity] = useState(''); 
    const [password, setPassword] = useState('');
    const [confirmPasswordValue, setConfirmPasswordValue] = useState(''); // State for confirm password
    const [name, setName] = useState(''); // State for the name field (optional for registration)

    const [isLoading, setIsLoading] = useState(false);
    const [message, setMessage] = useState<MessageState>({ type: null, text: '' });
    

    // --- Clear Message ---
    const clearMessage = () => setMessage({ type: null, text: '' });

    // --- Registration Logic ---
    const handleRegister = async () => {
        clearMessage();
        console.log(`[SRP Register] Starting registration for: ${identity}`); // Log start

        if (!identity || !password || !confirmPasswordValue) {
            console.warn("[SRP Register] Missing required fields."); // Log warning
            setMessage({ type: 'error', text: 'Please fill in all required fields.' });
            return;
        }
        if (password !== confirmPasswordValue) {
             console.warn("[SRP Register] Passwords do not match."); // Log warning
             setMessage({ type: 'error', text: 'Passwords do not match.' });
             return;
        }

        setIsLoading(true);

        try {
            // 1. Generate Salt
            const saltBuffer = await SRP.genKey(32);
            console.log(`[SRP Register] Generated Salt (Buffer):`, saltBuffer);
            console.log(`[SRP Register] Generated Salt (Hex): ${saltBuffer.toString('hex')}`);

            // 2. Compute Verifier
            console.log("[SRP Register] Computing Verifier with:", {
                params: 'SRP.params[4096]', // Indicate params used
                salt: saltBuffer.toString('hex'),
                identity: identity, // Log identity used
                password: '***' // Avoid logging raw password directly if possible
            });
            const verifierBuffer = SRP.computeVerifier(
                srpParams,
                saltBuffer,
                Buffer.from(identity),
                Buffer.from(password)
            );
            console.log(`[SRP Register] Computed Verifier (Buffer):`, verifierBuffer);
            console.log(`[SRP Register] Computed Verifier (Hex): ${verifierBuffer.toString('hex')}`);

            // 3. Send to Backend
            const registrationData = {
                username: identity, // Send email as username
                salt: saltBuffer.toString('hex'),
                verifier: verifierBuffer.toString('hex'),
            };
            console.log("[SRP Register] Sending registration data to backend:", registrationData);
            await axios.post(`${API_BASE_URL}api/auth/register`, registrationData);

            console.log(`[SRP Register] Registration successful for: ${identity}`); // Log success
            setMessage({ type: 'success', text: `User "${identity}" registered successfully. You can now log in.` });

            setPassword('');
            setConfirmPasswordValue('');

            switchMode('login'); // Switch to login mode

        } catch (error: any) {
            console.error("[SRP Register] Registration failed:", error); // Log the full error object
            let errorMessage = "Registration failed. Please try again.";
            if (axios.isAxiosError(error) && error.response) {
                const apiError = error.response.data?.error || JSON.stringify(error.response.data); // Try to get more details
                console.error(`[SRP Register] API Error (${error.response.status}):`, apiError); // Log API specific error
                if (error.response.status === 409) errorMessage = apiError || "User already exists.";
                else if (error.response.status === 400) errorMessage = apiError || "Invalid registration data.";
                else errorMessage = apiError || `Server error (${error.response.status}).`;
            } else if (error instanceof Error) {
                 console.error(`[SRP Register] Client-side Error: ${error.message}`); // Log client-side error
                errorMessage = error.message;
            }
            setMessage({ type: 'error', text: errorMessage });
        } finally {
            setIsLoading(false);
        }
    };

    // --- Login Logic ---
    const handleLogin = async () => {
        clearMessage();
         console.log(`[SRP Login] Starting login attempt for: ${identity}`); // Log start

        if (!identity || !password) {
             console.warn("[SRP Login] Missing username or password."); // Log warning
            setMessage({ type: 'error', text: 'Username (Email) and password are required.' });
            return;
        }
        setIsLoading(true);

        try {
            const step1Data = { username: identity };
            console.log("[SRP Login Step 1] Sending username to backend:", step1Data);
            const res = await axios.post<{ s: string; B: string }>(`${API_BASE_URL}api/auth/login/step1`, step1Data); // Corrected type for response

            const { s, B } = res.data; 
            if (!s || !B) {
                throw new Error("Server response missing salt or B.");
            }
            const secret1 = await SRP.genKey(32); 
            console.log(`[SRP Login Step 2] Generated client secret 'a' (secret1) (Hex): ${secret1.toString('hex')}`);

            const srpClient = new SrpClient(
                srpParams,
                Buffer.from(s, "hex"),
                Buffer.from(identity),
                Buffer.from(password),
                secret1
            );

            const srpA = srpClient.computeA();
            srpClient.setB(Buffer.from(B, 'hex')); // Set server B

            const M1 = srpClient.computeM1();
            const K = srpClient.computeK(); // Compute the session key

            // === SRP Step 2: Client -> Server (Send A, M1) ===
            const step2Data = {
                username: identity,
                A: srpA.toString('hex'), // Client public ephemeral 'A'
                M1: M1.toString('hex'), // Client proof 'M1'
            };
            // This request expects M2 from the server for full verification
            const step2Response = await axios.post<{ M2: string }>(`${API_BASE_URL}api/auth/login/step2`, step2Data); // Expect M2

            // === SRP Step 3: Server -> Client (Receive M2) ===
             const { M2 } = step2Response.data;
             if (!M2) {
                 throw new Error("Server response missing proof M2.");
             }

             try {
                 srpClient.checkM2(Buffer.from(M2, 'hex')); // Verify M2
             } catch (m2Error) {
                 // Throw specific error to be caught below
                 throw new Error("Invalid server proof (M2). Authentication failed.");
             }

            // If M2 verification passes, login is successful
            console.log(`[SRP Login] Login successful for: ${identity}`);
            setMessage({ type: 'success', text: `Login successful for ${identity}.` }); // Update success message

        } catch (error: any) {
            console.error("[SRP Login] Login failed:", error); // Log the full error
            let errorMessage = "Login failed. Please check credentials or try again.";
            if (axios.isAxiosError(error) && error.response) {
                const apiError = error.response.data?.error || JSON.stringify(error.response.data);
                 console.error(`[SRP Login] API Error (${error.response.status}):`, apiError);
                 // Specific SRP-related errors might come with 400 or 401
                 if (error.response.status === 401 || error.response.status === 404) errorMessage = apiError || "Invalid username or password.";
                 else if (error.response.status === 400) errorMessage = apiError || "Invalid login data (e.g., bad A or M1 format, session expired).";
                 else errorMessage = apiError || `Server error (${error.response.status}).`;
            } else if (error instanceof Error) {
                 console.error(`[SRP Login] Client-side/SRP Error: ${error.message}`);
                // Catch specific errors like the M2 verification failure
                if (error.message.includes("Invalid server proof")) errorMessage = "Login failed: Server authentication failed (Invalid M2).";
                else if (error.message.includes("missing salt or B")) errorMessage = "Login failed: Incomplete data from server step 1.";
                 else if (error.message.includes("missing proof M2")) errorMessage = "Login failed: Incomplete data from server step 2.";
                else errorMessage = `Client error: ${error.message}`; // General client error
            }
            setMessage({ type: 'error', text: errorMessage });
        } finally {
            setIsLoading(false);
        }
    };

    const isLoginMode = mode === 'login';

    // --- Handlers ---
    const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault(); // Prevent default HTML form submission
        console.log(`[Form Submit] Mode: ${mode}, Identity: ${identity}`); // Log form submit action
        clearMessage(); // Clear any previous messages

        // Call the appropriate handler based on the current mode
        if (mode === 'register') {
            handleRegister(); // Password match check is now inside handleRegister
        } else { // mode === 'login'
            handleLogin();
        }
    };

    // Function to switch modes
    const switchMode = (newMode: AuthMode) => {
         console.log(`[Mode Switch] Switching to: ${newMode}`); // Log mode switch
        setMode(newMode);
        // Reset password visibility
        setShowPassword(false);
        setShowConfirmPassword(false);
        // Clear form fields and messages when switching modes
        setName('');
        setIdentity('');
        setPassword('');
        setConfirmPasswordValue('');
        clearMessage();
        setIsLoading(false); // Reset loading state
    };

    // Toggle password visibility functions
    const togglePasswordVisibility = () => setShowPassword(prev => !prev);
    const toggleConfirmPasswordVisibility = () => setShowConfirmPassword(prev => !prev);


    return (
        <div className={cn("flex flex-col gap-6", className)} {...props}>
            <Card className="overflow-hidden">
                <CardContent className="grid p-0 md:grid-cols-2">
                    {/* === Form Section === */}
                    <form className="flex flex-col justify-center p-6 md:p-8" onSubmit={handleSubmit}>
                        <div className="flex flex-col gap-6">
                            {/* Header */}
                            <div className="flex flex-col items-center text-center mb-2">
                                <h1 className="text-2xl font-bold">
                                    {isLoginMode ? 'Welcome back' : 'Create an account'}
                                </h1>
                                <p className="text-balance text-muted-foreground">
                                    {isLoginMode
                                        ? 'Login to your SCS account'
                                        : 'Enter your information to get started'}
                                </p>
                            </div>

                            {/* Display Messages */}
                            {message.type && (
                                <div
                                    className={cn(
                                        "p-3 rounded-md text-sm",
                                        message.type === 'error' && "bg-red-100 text-red-700 border border-red-300",
                                        message.type === 'success' && "bg-green-100 text-green-700 border border-green-300"
                                    )}
                                    role="alert"
                                >
                                    {message.text}
                                </div>
                            )}

                            {/* Input Fields Container */}
                            <div className="grid gap-4">
                                {/* --- Name Field (Register Only - Animates) --- */}
                                <div
                                    className={cn(
                                        "grid gap-2",
                                        "overflow-hidden transition-all duration-500 ease-in-out",
                                        isLoginMode ? "max-h-0 opacity-0 mt-0" : "max-h-40 opacity-100"
                                    )}
                                >
                                    <Label htmlFor="name">Name</Label>
                                    <Input
                                        id="name"
                                        name="name"
                                        placeholder="Your Name"
                                        // required={!isLoginMode} // Optional, depends if name is truly required
                                        disabled={isLoginMode || isLoading} // Disable when loading
                                        aria-hidden={isLoginMode}
                                        value={name} // Bind value
                                        onChange={(e) => setName(e.target.value)} // Update state
                                    />
                                </div>

                                {/* --- Email Field (Always Visible - Use this for identity) --- */}
                                <div className="grid gap-2">
                                    <Label htmlFor="email">Email (Username)</Label>
                                    <Input
                                        id="email"
                                        name="email"
                                        type="email"
                                        placeholder="m@example.com"
                                        required
                                        value={identity} // Bind value to identity state
                                        onChange={(e) => setIdentity(e.target.value)} // Update identity state
                                        disabled={isLoading} // Disable when loading
                                    />
                                </div>

                                {/* --- Password Field (Always Visible, with Show/Hide) --- */}
                                <div className="grid gap-2">
                                    <div className="flex items-center">
                                        <Label htmlFor="password">Password</Label>
                                        {/* Forgot Password Link Wrapper (Login Only - Fades) */}
                                        <div
                                            className={cn(
                                                "ml-auto transition-opacity duration-300 ease-in-out delay-200",
                                                isLoginMode ? "opacity-100" : "opacity-0"
                                            )}
                                        >
                                            <a
                                                href="#"
                                                className={cn(
                                                    "text-sm underline-offset-2 hover:underline",
                                                    !isLoginMode && "pointer-events-none"
                                                )}
                                                aria-hidden={!isLoginMode}
                                                tabIndex={isLoginMode ? 0 : -1}
                                            >
                                                Forgot your password?
                                            </a>
                                        </div>
                                    </div>
                                    {/* Input and Icon Wrapper */}
                                    <div className="relative">
                                        <Input
                                            id="password"
                                            name="password"
                                            type={showPassword ? 'text' : 'password'} // Dynamic type
                                            required
                                            className="pr-10" // Add padding for the icon
                                            value={password} // Bind value to password state
                                            onChange={(e) => setPassword(e.target.value)} // Update password state
                                            disabled={isLoading} // Disable when loading
                                        />
                                        <Button
                                            type="button"
                                            variant="ghost"
                                            size="icon"
                                            className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 text-muted-foreground hover:text-foreground" // Position icon button
                                            onClick={togglePasswordVisibility} // Add click handler
                                            aria-label={showPassword ? "Hide password" : "Show password"}
                                            tabIndex={-1} // Prevent tabbing to the button itself
                                            disabled={isLoading} // Disable when loading
                                        >
                                            {showPassword
                                                ? <EyeOff className="h-4 w-4" />
                                                : <Eye className="h-4 w-4" />
                                            }
                                        </Button>
                                    </div>
                                </div>

                                {/* --- Confirm Password Field (Register Only - Animates, with Show/Hide) --- */}
                                <div
                                    className={cn(
                                        "grid gap-2",
                                        "overflow-hidden transition-all duration-500 ease-in-out",
                                        isLoginMode ? "max-h-0 opacity-0 mt-0" : "max-h-40 opacity-100"
                                    )}
                                >
                                    <Label htmlFor="confirm-password">Confirm Password</Label>
                                    {/* Input and Icon Wrapper */}
                                    <div className="relative">
                                        <Input
                                            id="confirm-password"
                                            name="confirmPassword"
                                            type={showConfirmPassword ? 'text' : 'password'} // Dynamic type
                                            required={!isLoginMode} // Required only in register mode
                                            disabled={isLoginMode || isLoading} // Disable when loading or in login mode
                                            aria-hidden={isLoginMode}
                                            className="pr-10" // Add padding for the icon
                                            value={confirmPasswordValue} // Bind value
                                            onChange={(e) => setConfirmPasswordValue(e.target.value)} // Update state
                                        />
                                        <Button
                                            type="button"
                                            variant="ghost"
                                            size="icon"
                                            className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 text-muted-foreground hover:text-foreground" // Position icon button
                                            onClick={toggleConfirmPasswordVisibility} // Add click handler
                                            aria-label={showConfirmPassword ? "Hide confirmation password" : "Show confirmation password"}
                                            // Only interactive when the field is visible and not loading
                                            style={{ display: isLoginMode ? 'none' : 'inline-flex' }}
                                            tabIndex={-1} // Prevent tabbing to the button itself
                                            disabled={isLoading} // Disable when loading
                                        >
                                            {showConfirmPassword
                                                ? <EyeOff className="h-4 w-4" />
                                                : <Eye className="h-4 w-4" />
                                            }
                                        </Button>
                                    </div>
                                </div>
                            </div> {/* End Input Fields Container */}

                            {/* Submit Button */}
                            <Button type="submit" className="w-full mt-2" disabled={isLoading}>
                                {isLoading
                                    ? <>{isLoginMode ? 'Logging in...' : 'Creating account...'}</>
                                    : isLoginMode ? 'Login' : 'Create account'
                                }
                            </Button>

                            {/* === Rest of the form (Social Logins, Switch Mode Link) remains the same === */}
                            {/* Social Logins Separator ... */}
                            <div className="relative text-center text-sm after:absolute after:inset-0 after:top-1/2 after:z-0 after:flex after:items-center after:border-t after:border-border">
                                <span className="relative z-10 bg-background px-2 text-muted-foreground">
                                    {isLoginMode ? 'Or continue with' : 'Or sign up with'}
                                </span>
                            </div>
                            {/* Social Login Buttons ... */}
                             <div className="grid grid-cols-2 gap-4">
                                {/* Apple */}
                                <Button variant="outline" className="w-full" type="button" aria-label="Sign in with Microsoft" disabled={isLoading || true}>
                                {/* Microsoft Logo SVG */}
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21" className="h-4 w-4 mr-2">
                                    {/* Red Square */}
                                    <rect x="1" y="1" width="9" height="9" fill="#F25022" />
                                    {/* Green Square */}
                                    <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
                                    {/* Blue Square */}
                                    <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
                                    {/* Yellow Square */}
                                    <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
                                </svg>
                                Microsoft
                            </Button>
                                {/* Google */}
                                <Button variant="outline" className="w-full" type="button" aria-label="Sign in with Google" disabled={isLoading || true}>
                                     <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" className="h-4 w-4 mr-2"> <path d="M12.48 10.92v3.28h7.84c-.24 1.84-.853 3.187-1.787 4.133-1.147 1.147-2.933 2.4-6.053 2.4-4.827 0-8.6-3.893-8.6-8.72s3.773-8.72 8.6-8.72c2.6 0 4.507 1.027 5.907 2.347l2.307-2.307C18.747 1.44 16.133 0 12.48 0 5.867 0 .307 5.387.307 12s5.56 12 12.173 12c3.573 0 6.267-1.173 8.373-3.36 2.16-2.16 2.84-5.213 2.84-7.667 0-.76-.053-1.467-.173-2.053H12.48z" fill="currentColor" /> </svg>
                                    Google
                                </Button>
                            </div>
                             {/* Switch Mode Link/Button */}
                            <div className="text-center text-sm mt-2">
                                {isLoginMode ? (
                                    <>
                                        Don&apos;t have an account?{' '}
                                        <button
                                            type="button"
                                            onClick={() => switchMode('register')}
                                            className="font-medium text-primary underline underline-offset-4 hover:text-primary/90"
                                            disabled={isLoading} // Disable when loading
                                        >
                                            Sign up
                                        </button>
                                    </>
                                ) : (
                                    <>
                                        Already have an account?{' '}
                                        <button
                                            type="button"
                                            onClick={() => switchMode('login')}
                                            className="font-medium text-primary underline underline-offset-4 hover:text-primary/90"
                                            disabled={isLoading} // Disable when loading
                                        >
                                            Log in
                                        </button>
                                    </>
                                )}
                            </div>
                        </div> {/* End Inner Form Flex Col */}
                    </form>

                     {/* === Image Section === */}
                    <div className="hidden h-full items-center justify-center bg-white p-6 md:flex">
                        <img
                            src={logo} // Replace with your image path
                            alt="Visual representation for authentication"
                            className="max-h-[80%] max-w-[80%] rounded-lg object-contain dark:brightness-[0.8]"
                        />
                    </div>
                </CardContent>
            </Card>

            {/* === Terms and Policy === */}
            <div className="text-balance text-center text-xs text-muted-foreground [&_a]:underline [&_a]:underline-offset-4 hover:[&_a]:text-primary">
                By clicking continue, you agree to our <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>.
            </div>
        </div>
    );
}
