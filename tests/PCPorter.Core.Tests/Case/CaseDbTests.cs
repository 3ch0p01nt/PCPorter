using PCPorter.Core.Case;

namespace PCPorter.Core.Tests.Case;

public class CaseDbTests : IDisposable
{
    readonly string _path = Path.Combine(Path.GetTempPath(), $"case-{Guid.NewGuid():N}.db");
    public void Dispose() { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); File.Delete(_path); }

    static Artifact Visit(string url, DateTimeOffset ts) => new(
        TsUtc: ts, Category: "WebHistory", Source: "Chrome/Default", ArtifactName: "History.visits",
        User: "bob", Action: "Visit", Subject: url, Detail: "typed", Confidence: Confidence.Existed);

    [Fact] public void Insert_and_count_by_category()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("https://example.com", DateTimeOffset.UtcNow), Visit("https://contoso.com", DateTimeOffset.UtcNow)]);
        Assert.Equal(2, db.CountByCategory()["WebHistory"]);
    }

    [Fact] public void Full_text_search_finds_subject_and_detail()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("https://example.com/cats", DateTimeOffset.UtcNow), Visit("https://contoso.com", DateTimeOffset.UtcNow)]);
        var hits = db.Search("cats");
        Assert.Single(hits);
        Assert.Contains("cats", hits[0].Subject);
    }

    [Fact] public void Reopen_keeps_data_and_schema_version()
    {
        using (var db = CaseDb.Open(_path)) db.Insert([Visit("https://a.com", DateTimeOffset.UtcNow)]);
        using var again = CaseDb.Open(_path);
        Assert.Equal(CaseDb.CurrentSchema, again.SchemaVersion);
        Assert.Equal(1, again.CountByCategory()["WebHistory"]);
    }

    [Fact] public void Version_1_case_is_upgraded_and_keeps_artifacts()
    {
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE artifacts(id INTEGER PRIMARY KEY, ts_utc INTEGER, category TEXT NOT NULL, source TEXT NOT NULL,
                  artifact TEXT NOT NULL, user TEXT, action TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT, confidence INTEGER NOT NULL);
                CREATE VIRTUAL TABLE artifacts_fts USING fts5(subject, detail, content='artifacts', content_rowid='id');
                CREATE TRIGGER artifacts_ai AFTER INSERT ON artifacts BEGIN
                  INSERT INTO artifacts_fts(rowid, subject, detail) VALUES (new.id, new.subject, new.detail);
                END;
                CREATE TABLE tags(artifact_id INTEGER NOT NULL, tag TEXT NOT NULL, note TEXT, PRIMARY KEY(artifact_id, tag));
                INSERT INTO artifacts(category, source, artifact, action, subject, confidence) VALUES ('WebHistory','x','y','Visit','https://old',0);
                INSERT INTO tags VALUES (1, 'Important', 'look later');
                PRAGMA user_version = 1;
                """;
            cmd.ExecuteNonQuery();
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        using var db = CaseDb.Open(_path);
        Assert.Equal(2, db.SchemaVersion);
        Assert.Equal(1, db.CountByCategory()["WebHistory"]);
        Assert.Equal(("artifact:1", "artifact", "Important"), Assert.Single(db.Tags()));   // v1 tags kept
        db.BeginScan(new ScanInfo("s1", DateTimeOffset.UtcNow, "t", "live", null, null, null, null));
        Assert.Equal("s1", Assert.Single(db.Scans()).ScanId);
        db.Insert([Visit("https://new/searchable", DateTimeOffset.UtcNow)]);
        Assert.Single(db.Search("searchable"));                                              // search still works after upgrade
    }

    [Fact] public void Closing_the_case_releases_the_file()
    {
        using (var db = CaseDb.Open(_path)) db.Insert([Visit("https://a.com", DateTimeOffset.UtcNow)]);
        File.Move(_path, _path + ".moved");                       // would fail if a pooled connection still held it
        File.Move(_path + ".moved", _path);
    }

    [Fact] public void Transaction_saves_all_or_nothing()
    {
        using var db = CaseDb.Open(_path);
        db.BeginScan(new ScanInfo("s", DateTimeOffset.UtcNow, "t", "live", null, null, null, null));
        Assert.Throws<InvalidOperationException>(() => db.RunInTransaction(() =>
        {
            db.SaveItems("s", [new("apps", "a", "{}")]);
            throw new InvalidOperationException("boom");
        }));
        Assert.Empty(db.Items("s"));
        db.RunInTransaction(() => db.SaveItems("s", [new("apps", "a", "{}"), new("apps", "a", "{\"dup\":1}")]));
        Assert.Equal("{}", Assert.Single(db.Items("s")).Json);   // duplicate key keeps the first, never silently replaced
    }

    [Fact] public void Search_finds_text_containing_quotes()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("say \"hi\" there", DateTimeOffset.UtcNow)]);
        Assert.Single(db.Search("\"hi\""));
        Assert.Empty(db.Search(""));
    }

    [Fact] public void Newer_case_is_refused()
    {
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version = 99;";
            cmd.ExecuteNonQuery();
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Assert.Throws<CaseTooNewException>(() => CaseDb.Open(_path));
    }

    [Fact] public void Scans_items_diff_and_tags()
    {
        using var db = CaseDb.Open(_path);
        db.BeginScan(new ScanInfo("old", DateTimeOffset.UnixEpoch, "1", "live", "m", "PC", "26200", @"C:\"));
        db.BeginScan(new ScanInfo("new", DateTimeOffset.UnixEpoch.AddDays(1), "1", "live", "m", "PC", "26200", @"C:\"));
        db.SaveItems("old", [new("apps", "7zip", "{\"v\":1}"), new("apps", "gone", "{}")]);
        db.SaveItems("new", [new("apps", "7zip", "{\"v\":2}"), new("apps", "added", "{}")]);
        db.RecordCollector("new", "Installed apps", "Ok", 2, 120, null);
        db.FinishScan("new", DateTimeOffset.UnixEpoch.AddDays(1).AddMinutes(1), "ok");

        var d = db.Diff("old", "new", "apps");
        Assert.Equal(["added"], d.Added);
        Assert.Equal(["gone"], d.Removed);
        Assert.Equal(["7zip"], d.Changed);
        Assert.Equal(["old", "new"], db.Scans().Select(s => s.ScanId));

        db.SetTag("7zip", "apps", "I know this one");
        Assert.Equal(("7zip", "apps", "I know this one"), Assert.Single(db.Tags()));
    }

    [Fact] public void Search_input_with_quotes_is_safe()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("https://a.com", DateTimeOffset.UtcNow)]);
        Assert.Empty(db.Search("\" OR 1=1 --"));
    }
}
