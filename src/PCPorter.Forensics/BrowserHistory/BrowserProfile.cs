namespace PCPorter.Forensics.BrowserHistory;

/// <summary>How a browser stores its history: Chromium SQLite, Firefox places.sqlite, or the IE/legacy Edge ESE cache.</summary>
public enum BrowserFamily { Chromium, Firefox, WebCache }

/// <summary>One browser profile of one Windows account.</summary>
/// <param name="User">The Windows account name.</param>
/// <param name="Browser">Display name, e.g. "Google Chrome".</param>
/// <param name="Name">The profile's display name (from Chromium's Local State when known), e.g. "Default" or "Work".</param>
/// <param name="Folder">Readable path of the profile folder.</param>
public sealed record BrowserProfile(string User, string Browser, BrowserFamily Family, string Name, string Folder);
