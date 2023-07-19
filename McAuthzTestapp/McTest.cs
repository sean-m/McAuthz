#nullable disable
namespace SMM {
    public static class Assert {

        public static void NotNull(string input, string message = null) {
#if DEBUG
            if (string.IsNullOrEmpty(input)) {
                throw new ArgumentNullException($"Assertion failed: input string null or empty. {message}");
            }
#endif
        }

        public static void NotNull(dynamic input, string message=null) {
#if DEBUG
            if (input == null) {
                throw new ArgumentNullException($"Assertion failed: input object null. {message}");
            }
#endif
        }

        public static void IsNull(string input, string message = null) {
#if DEBUG
            if (!string.IsNullOrEmpty(input)) {
                throw new ArgumentNullException($"Assertion failed: input string should be null or empty. {message}");
            }
#endif
        }

        public static void IsNull(dynamic input, string message = null) {
#if DEBUG
            if (input != null) {
                throw new ArgumentNullException($"Assertion failed: input object should be null. {message}");
            }
#endif
        }
    }
}
