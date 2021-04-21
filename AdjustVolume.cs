using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace AdjustVolume {
	[StructLayout(LayoutKind.Sequential)]
	public struct RECT {
		public int Left, Top, Right, Bottom;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct POINT {
		public int X, Y;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct MOUSEINPUT {
		public int dx;
		public int dy;
		public uint mouseData;
		public uint dwFlags;
		public uint time;
		public UIntPtr dwExtraInfo;
	}

	[StructLayout(LayoutKind.Explicit)]
	public struct InputUnion {
		[FieldOffset(0)]
		public MOUSEINPUT mi;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct INPUT {
		public uint type;
		public InputUnion DUMMYUNIONNAME;
	}

	public static class NativeMethods {
		public const uint MEM_COMMIT = 0x1000;
		public const uint PAGE_READWRITE = 0x04;
		public const uint MEM_RELEASE = 0x00008000;
		public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
		public const int LVIR_BOUNDS = 0;
		public const uint INPUT_MOUSE = 0;
		public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
		public const uint MOUSEEVENTF_LEFTUP = 0x0004;

		[return: MarshalAs(UnmanagedType.Bool)]
		public delegate bool WndEnumProc(
			IntPtr hWnd,
			IntPtr lParam);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAllocEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			uint dwSize,
			uint flAllocationType,
			uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool VirtualFreeEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			uint dwSize,
			uint dwFreeType);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			uint nSize,
			out uint lpNumberOfBytesWritten);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool ReadProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			[Out]
			byte[] lpBuffer,
			uint nSize,
			out uint lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(
			uint dwDesiredAccess,
			[MarshalAs(UnmanagedType.Bool)]
			bool bInheritHandle,
			uint dwProcessId);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CloseHandle(
			IntPtr hObject);

		[DllImport("user32.dll", CharSet = CharSet.Unicode)]
		public static extern IntPtr SendMessageW(
			IntPtr hWnd,
			int msg,
			int wParam,
			IntPtr lParam);

		[DllImport("user32.dll")]
		public static extern bool ClientToScreen(
			IntPtr hWnd,
			ref POINT lpPoint);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern uint SendInput(
			uint cInputs,
			[MarshalAs(UnmanagedType.LPArray), In]
			INPUT[] pInputs,
			int cbSize);

		[DllImport("user32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetCursorPos(
			int x,
			int y);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern int GetWindowTextLengthW(
			IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern int GetWindowTextW(
			IntPtr hWnd,
			StringBuilder lpString,
			int nMaxCount);

		[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern int GetClassNameW(
			IntPtr hWnd,
			StringBuilder lpClassName,
			int nMaxCount);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool IsWindowVisible(
			IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool GetWindowRect(
			IntPtr hWnd,
			out RECT lpRect);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool EnumThreadWindows(
			uint dwThreadId,
			WndEnumProc lpEnumFunc,
			IntPtr lParam);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool EnumChildWindows(
			IntPtr hWndParent,
			WndEnumProc lpEnumFunc,
			IntPtr lParam);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetForegroundWindow(
			IntPtr hWnd);
	}

	public static class Logger {
		public static void Log(string format, params object[] args) {
			var message = string.Format(format, args);
			Console.WriteLine("[{0:MM/dd/yyyy HH:mm:ss}] {1}", DateTime.Now, message);
		}
	}

	public class RemoteMarshalStruct<T> : IDisposable where T: struct {
		private IntPtr remoteBuffer;

		public RemoteMarshalStruct(T value) {
			Allocate();
			CopyToRemote(value);
		}

		public void Dispose() {
			Free();
		}

		private void Allocate() {
			remoteBuffer = NativeMethods.VirtualAllocEx(
				Program.Instance.ProcessHandle,
				IntPtr.Zero,
				(uint)Marshal.SizeOf<T>(),
				NativeMethods.MEM_COMMIT,
				NativeMethods.PAGE_READWRITE);
			if (remoteBuffer == IntPtr.Zero) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");
			}
		}

		private void Free() {
			if (remoteBuffer != IntPtr.Zero) {
				NativeMethods.VirtualFreeEx(
					Program.Instance.ProcessHandle,
					remoteBuffer,
					0,
					NativeMethods.MEM_RELEASE);
			}
		}

		private void CopyToRemote(T value) {
			uint bytesWritten;
			var bytes = ToBytes(value);
			var result = NativeMethods.WriteProcessMemory(
				Program.Instance.ProcessHandle,
				remoteBuffer,
				bytes,
				(uint)bytes.Length,
				out bytesWritten);
			if (!result || bytesWritten == 0) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
			}
		}

		private byte[] CopyFromRemote() {
			var readBuffer = new byte[Marshal.SizeOf<T>()];
			uint bytesRead;
			var result = NativeMethods.ReadProcessMemory(
				Program.Instance.ProcessHandle,
				remoteBuffer,
				readBuffer,
				(uint)Marshal.SizeOf<T>(),
				out bytesRead);
			if (!result || bytesRead == 0) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
			}
			return readBuffer;
		}

		private static byte[] ToBytes(T value) {
			var size = Marshal.SizeOf(value);
			var bytes = new byte[size];
			var pointer = Marshal.AllocHGlobal(size);
			try {
				Marshal.StructureToPtr(value, pointer, true);
				Marshal.Copy(pointer, bytes, 0, size);
				return bytes;
			} finally {
				Marshal.FreeHGlobal(pointer);
			}
		}

		private static T FromBytes(byte[] bytes) {
			var size = Marshal.SizeOf<T>();
			var pointer = Marshal.AllocHGlobal(size);
			try {
				Marshal.Copy(bytes, 0, pointer, size);
				return (T)Marshal.PtrToStructure(pointer, typeof(T));
			} finally {
				Marshal.FreeHGlobal(pointer);
			}
		}

		public IntPtr Param { get { return remoteBuffer; } }
		public T Value { get { return FromBytes(CopyFromRemote()); } }
	}

	public class RemoteProcess : IDisposable {
		private IntPtr hProcess;

		public RemoteProcess(uint dwProcessId) {
			hProcess = NativeMethods.OpenProcess(
				NativeMethods.PROCESS_ALL_ACCESS,
				false,
				dwProcessId);
			if (hProcess == IntPtr.Zero) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");
			}
		}

		public void Dispose() {
			if (hProcess != IntPtr.Zero) {
				NativeMethods.CloseHandle(hProcess);
			}
		}

		public IntPtr Handle { get { return hProcess; } }
	}

	public class Window {
		protected IntPtr hWnd;

		public Window(IntPtr hWnd) {
			this.hWnd = hWnd;
		}

		public Window(Window other) {
			this.hWnd = other.hWnd;
		}

		public bool SetForegroundWindow() {
			return NativeMethods.SetForegroundWindow(hWnd);
		}

		public List<Window> Children { get { return GetWindows(hWnd, NativeMethods.EnumChildWindows); } }
		public bool IsVisible { get { return NativeMethods.IsWindowVisible(hWnd); } }

		public string Text {
			get {
				var length = NativeMethods.GetWindowTextLengthW(hWnd);
				if (length == 0) {
					return string.Empty;
				}
				var windowText = new StringBuilder(length + 1);
				var result = NativeMethods.GetWindowTextW(hWnd, windowText, length + 1);
				if (result == 0) {
					return string.Empty;
				}
				return windowText.ToString();
			}
		}

		public string ClassName {
			get {
				var className = new StringBuilder(256);
				var result = NativeMethods.GetClassNameW(hWnd, className, className.Capacity);
				if (result == 0) {
					return string.Empty;
				}
				return className.ToString();
			}
		}

		public RECT Rect {
			get {
				RECT rect;
				var result = NativeMethods.GetWindowRect(hWnd, out rect);
				if (!result) {
					throw new Win32Exception(Marshal.GetLastWin32Error(), "GetWindowRect failed.");
				}
				return rect;
			}
		}

		public RECT ToScreen(RECT rect) {
			var topLeft = new POINT { X = rect.Left, Y = rect.Top };
			var bottomRight = new POINT { X = rect.Right, Y = rect.Bottom };
			NativeMethods.ClientToScreen(hWnd, ref topLeft);
			NativeMethods.ClientToScreen(hWnd, ref bottomRight);
			return new RECT {
				Top = topLeft.Y,
				Left = topLeft.X,
				Bottom = bottomRight.Y,
				Right = bottomRight.X
			};
		}

		[return: MarshalAs(UnmanagedType.Bool)]
		public static bool WndEnumProcCallback(IntPtr hWnd, IntPtr lParam) {
			var handles = (List<Window>)GCHandle.FromIntPtr(lParam).Target;
			handles.Add(new Window(hWnd));
			return true;
		}

		public static List<Window> GetWindows<T>(
			T parent,
			Func<T, NativeMethods.WndEnumProc, IntPtr, bool> enumerator
		) {
			var windows = new List<Window>();
			var param = GCHandle.Alloc(windows);
			try {
				enumerator(
					parent,
					new NativeMethods.WndEnumProc(Window.WndEnumProcCallback),
					GCHandle.ToIntPtr(param));
			} finally {
				param.Free();
			}
			return windows;
		}

		public static List<Window> GetThreadWindows(uint dwThreadId) {
			return GetWindows(dwThreadId, NativeMethods.EnumThreadWindows);
		}

		public void ClickOkButton() {
			Mouse.SetPosCenterRect(Children.OkButton().Rect);
			Mouse.Click();
			Thread.Sleep(TimeSpan.FromMilliseconds(100));
		}
	}

	public class ListView : Window {
		public ListView(Window window) : base(window) {
		}

		public RECT GetItemRect(int index, int flags) {
			const int LVM_GETITEMRECT = 4110;
			var rect = new RECT {
				Left = flags,
				Top = 0,
				Right = 0,
				Bottom = 0
			};
			using (var remoteRect = new RemoteMarshalStruct<RECT>(rect)) {
				var result = NativeMethods.SendMessageW(
					hWnd,
					LVM_GETITEMRECT,
					index,
					remoteRect.Param);
				if (result.ToInt32() == 0) {
					throw new InvalidOperationException("SendMessageW(LVM_GETITEMRECT) failed");
				}
				return remoteRect.Value;
			}
		}

		public void DoubleClickItem(int index) {
			Mouse.SetPosCenterRect(ToScreen(GetItemRect(index, NativeMethods.LVIR_BOUNDS)));
			Mouse.DoubleClick();
			Thread.Sleep(TimeSpan.FromMilliseconds(500));
		}
	}

	public class TabControl : Window {
		public TabControl(Window window) : base(window) {
		}

		public RECT GetItemRect(int index) {
			const int TCM_GETITEMRECT = 4874;
			var rect = new RECT {
				Left = 0,
				Top = 0,
				Right = 0,
				Bottom = 0
			};
			using (var remoteRect = new RemoteMarshalStruct<RECT>(rect)) {
				var result = NativeMethods.SendMessageW(
					hWnd,
					TCM_GETITEMRECT,
					index,
					remoteRect.Param);
				if (result.ToInt32() == 0) {
					throw new InvalidOperationException("SnedMessageW(TCM_GETITEMRECT) failed.");
				}
				return remoteRect.Value;
			}
		}

		public void ClickItem(int index) {
			Mouse.SetPosCenterRect(ToScreen(GetItemRect(index)));
			Mouse.Click();
			Thread.Sleep(TimeSpan.FromMilliseconds(100));
		}
	}

	public class Trackbar : Window {
		public Trackbar(Window window) : base(window) {
		}

		public int Pos {
			get {
				const int TBM_GETPOS = 1024;
				return NativeMethods.SendMessageW(hWnd, TBM_GETPOS, 0, IntPtr.Zero).ToInt32();
			}
		}

		public void SetPosNotify(int pos) {
			const int TBM_SETPOSNOTIFY = 1058;
			NativeMethods.SendMessageW(hWnd, TBM_SETPOSNOTIFY, 0, (IntPtr)pos);
		}
	}

	public static class Mouse {
		public static void Click() {
			var inputEvent = new INPUT {
				type = NativeMethods.INPUT_MOUSE,
				DUMMYUNIONNAME = new InputUnion {
					mi = new MOUSEINPUT {
						dx = 0,
						dy = 0,
						mouseData = 0,
						dwFlags = NativeMethods.MOUSEEVENTF_LEFTDOWN | NativeMethods.MOUSEEVENTF_LEFTUP,
						time = 0,
						dwExtraInfo = UIntPtr.Zero
					}
				}
			};
			var count = NativeMethods.SendInput(1, new[] { inputEvent }, Marshal.SizeOf(inputEvent));
			if (count == 0) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "SendInput failed.");
			}
		}

		public static void DoubleClick() {
			Click();
			Click();
		}

		private static void SetPos(int x, int y) {
			var result = NativeMethods.SetCursorPos(x, y);
			if (!result) {
				throw new Win32Exception(Marshal.GetLastWin32Error(), "SetCursorPos failed.");
			}
		}

		public static void SetPosCenterRect(RECT rect) {
			var centerX = rect.Left + (rect.Right - rect.Left) / 2;
			var centerY = rect.Top + (rect.Bottom - rect.Top) / 2;
			SetPos(centerX, centerY);
		}
	}

	public static class IEnumberableWindowExtensions {
		public static IEnumerable<Window> WithClass(this IEnumerable<Window> windows, string className) {
			return windows.Where(window => window.ClassName == className);
		}

		public static IEnumerable<Window> WithText(this IEnumerable<Window> windows, string text) {
			return windows.Where(window => window.Text == text);
		}

		public static IEnumerable<Window> Dialogs(this IEnumerable<Window> windows) {
			const string DialogClassName = "#32770";
			return windows.WithClass(DialogClassName);
		}

		public static IEnumerable<Window> Visible(this IEnumerable<Window> windows) {
			return windows.Where(window => window.IsVisible);
		}

		public static Window FirstVisibleDialog(this IEnumerable<Window> windows) {
			return windows.Visible().Dialogs().First();
		}

		public static Window SoundDialog(this IEnumerable<Window> windows) {
			return windows.Visible().Dialogs().WithText("Sound").FirstOrDefault();
		}

		public static Window WebCamMicDialog(this IEnumerable<Window> windows) {
			return windows.Visible().Dialogs().WithText("WebCam Mic Properties").First();
		}

		public static Window OkButton(this IEnumerable<Window> windows) {
			return windows.Visible().WithClass("Button").WithText("OK").First();
		}

		public static ListView ListView(this IEnumerable<Window> windows) {
			return new ListView(windows.Visible().WithClass("SysListView32").First());
		}

		public static TabControl TabControl(this IEnumerable<Window> windows) {
			return new TabControl(windows.Visible().WithClass("SysTabControl32").First());
		}

		public static Trackbar Trackbar(this IEnumerable<Window> windows) {
			return new Trackbar(windows.Visible().WithClass("msctls_trackbar32").First());
		}
	}

	public class Program : IDisposable {
		private Process process;
		private RemoteProcess remoteProcess;
		private static Program instance;

		public static Program Instance { get { return instance; } }

		public static void Run() {
			using (var program = new Program()) {
				program.SetMicLevel(10);
			}
		}

		public Program() {
			if (instance != null) {
				throw new InvalidOperationException("Program singleton violation.");
			}
			instance = this;
			Logger.Log("Launching rundll32 for mmsys.cpl...");
			var args = new[] {
				@"c:\windows\system32\shell32.dll,Control_RunDLL",
				@"c:\windows\system32\mmsys.cpl",
				",1"
			};
			process = Process.Start("rundll32.exe", string.Join(" ", args));
			Logger.Log("Process ID: {0}", process.Id);
			remoteProcess = new RemoteProcess((uint)process.Id);
			Thread.Sleep(TimeSpan.FromMilliseconds(1000));
		}

		public void Dispose() {
			instance = null;
			if (remoteProcess != null) {
				remoteProcess.Dispose();
			}
			if (process == null) {
				return;
			}
			if (!process.WaitForExit(1000)) {
				process.Kill();
			}
			process.Dispose();
		}

		public void SetMicLevel(int level) {
			Logger.Log("Finding window thread hosting the Sound Dialog...");
			var windowThreadId = FindWindowThread();
			Logger.Log("Window thread ID: {0}", windowThreadId);

			Logger.Log("Opening WebCam Mic Dialog...");
			var soundDialog = Window.GetThreadWindows(windowThreadId).SoundDialog();
			if (!soundDialog.SetForegroundWindow()) {
				throw new InvalidOperationException("Could not bring the sound dialog to the foreground.");
			}
			const int webCamMicIndex = 1;
			soundDialog
				.Children.FirstVisibleDialog()
				.Children.ListView()
				.DoubleClickItem(webCamMicIndex);

			Logger.Log("Switching to the levels tab...");
			var webCamMicDialog = Window.GetThreadWindows(windowThreadId).WebCamMicDialog();
			const int levelsTabIndex = 2;
			webCamMicDialog
				.Children.TabControl()
				.ClickItem(levelsTabIndex);

			Logger.Log("Finding the level trackbar...");
			var trackbar = webCamMicDialog
				.Children.FirstVisibleDialog()
				.Children.FirstVisibleDialog()
				.Children.Trackbar();
			var currentLevel = trackbar.Pos;
			Logger.Log("Current level: {0}", currentLevel);
			if (level == currentLevel) {
				Logger.Log("No need to switch level.");
				return;
			}

			Logger.Log("Setting new level to: {0}", level);
			trackbar.SetPosNotify(level);

			Logger.Log("Closing WebCam Mic Dialog...");
			webCamMicDialog.ClickOkButton();

			Logger.Log("Closing Sound Dialog...");
			soundDialog.ClickOkButton();
		}

		public IntPtr ProcessHandle { get { return remoteProcess.Handle; } }

		private uint FindWindowThread() {
			return process
				.Threads
				.Cast<ProcessThread>()
				.Select(thread => (uint)thread.Id)
				.First(threadId => Window.GetThreadWindows(threadId).SoundDialog() != null);
		}
	}
}
