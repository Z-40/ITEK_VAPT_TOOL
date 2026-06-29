import { useState } from "react";
import { Shield } from "lucide-react"; // or use your inline icons

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    // Simulate API call
    setTimeout(() => {
      alert("Login successful (demo)");
      setLoading(false);
    }, 1200);
  };

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-6">
      {/* Background effects */}
      <div className="absolute inset-0 bg-[radial-gradient(#10b981_0.8px,transparent_1px)] bg-[length:40px_40px] opacity-10" />

      <div className="w-full max-w-md relative z-10">
        <div className="flex justify-center mb-8">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-gradient-to-br from-emerald-400 to-cyan-400 rounded-2xl flex items-center justify-center">
              <Shield className="w-7 h-7 text-black" />
            </div>
            <div>
              <div className="text-3xl font-bold tracking-tighter">ITEK</div>
              <div className="text-xs text-emerald-400 -mt-1 font-mono">VAPT PLATFORM</div>
            </div>
          </div>
        </div>

        <div className="bg-zinc-950 border border-white/10 rounded-3xl p-10 shadow-2xl">
          <h2 className="text-3xl font-bold text-center mb-2">Access the Arsenal</h2>
          <p className="text-gray-400 text-center mb-8">Sign in to continue your engagement</p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Email / Username</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="you@company.com"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black border border-white/20 focus:border-emerald-500 rounded-2xl px-5 py-4 outline-none transition"
                placeholder="••••••••"
                required
              />
            </div>

            <div className="flex justify-between text-sm">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" className="accent-emerald-500" />
                <span className="text-gray-400">Remember me</span>
              </label>
              <a href="#" className="text-emerald-400 hover:underline">Forgot password?</a>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-emerald-400 to-cyan-400 text-black font-semibold py-4 rounded-2xl text-lg hover:brightness-110 transition disabled:opacity-70"
            >
              {loading ? "BREACHING..." : "ENTER THE GRID"}
            </button>
          </form>

          <div className="text-center mt-8 text-sm text-gray-500">
            Don't have an account?{" "}
            <a href="/signup" className="text-emerald-400 hover:underline">Create one</a>
          </div>
        </div>

        <div className="text-center mt-8 text-xs text-gray-600">
          © 2026 ITEK • Offensive Security Platform
        </div>
      </div>
    </div>
  );
}