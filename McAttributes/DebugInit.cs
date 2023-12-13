using McAttributes.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.SqlServer.Storage.Internal;
using Npgsql;
using SMM;
using System.Linq;
using System.Reflection;

namespace McAttributes {
    public static class DebugInit {
        public async static void DbInit(NpgsqlConnection conn) {
            if (conn == null) throw new ArgumentNullException("Gonna hand me a viable databse connection.");
            if (conn.State != System.Data.ConnectionState.Open) {
                throw new Exception("Database connection is borkened. I need a working/opened one!");
            }

            var csvReader = new CsvFileReader(@"./test_values.csv", true);
            var _ = csvReader.ReadFileValues().FirstOrDefault();
                        
            var types = new Dictionary<string, Type>();
            var azuser = System.Reflection.TypeInfo.GetType("McAttributes.Models.User");


            Type GetParamType(string name) {
                if (types.ContainsKey(name)) return types[name];

                var prop = azuser?.GetProperties().FirstOrDefault(x => x.Name.ToString().Equals(name, StringComparison.CurrentCultureIgnoreCase));
                if (prop == null) {
                    throw new Exception($"Cannot resolve property with name: {name} on class 'Models.User'");
                }

                types.Add(name, prop.PropertyType);
                return prop.PropertyType;
            }

            var inserts = new List<Task>();

            csvReader = new CsvFileReader(@"./test_values.csv");
            foreach (var row in csvReader.ReadFileValues())
            {
                var columns = row.Keys.Where(k => !String.IsNullOrEmpty(row.GetValueOrDefault(k)));

                var paramQuery = @$"
                insert into azusers ({String.Join(',', columns)})
                values ({String.Join(',', columns.Select(x => $"@{x}"))})
                on conflict(aadid)
                do nothing;
                ";
                var sqlCmd = new NpgsqlCommand(paramQuery, conn);
                foreach (var col in columns)
                {
                    var type = GetParamType(col);
                    object value = GetAsType(row[col], type);
                    sqlCmd.Parameters.Add(new NpgsqlParameter($"@{col}", value));
                }
                inserts.Add(sqlCmd.ExecuteNonQueryAsync());
            }

            await Task.WhenAll(inserts.ToArray());
        }

        public static void DbInit(IdDbContext context) {
            if (context == null) throw new ArgumentNullException("Gonna hand me a viable databse connection.");

            UglyDbInitHelper.DbInit<Models.User>(context, @"./test_values.csv");
        }

        public static void DbInit<T>(IdDbContext context) {
            if (context == null) throw new ArgumentNullException("Gonna hand me a viable databse connection.");

            UglyDbInitHelper.DbInit<T>(context, @"./test_values.csv");
        }

        static object? GetAsType(object source, Type desiredType) {
            if (source == null) return source;

            string strSrc = source.ToString();
            if (string.IsNullOrEmpty(strSrc)) {
                return null;
            }

            if (desiredType == typeof(Guid)) {
                return Guid.Parse(source.ToString());
            } else if (desiredType == typeof(DateTime?)) {
                return DateTime.Parse(source.ToString());
            }

            return Convert.ChangeType(source, desiredType);
        }
    }
}
