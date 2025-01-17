﻿using System;
using System.Collections.Generic;
using System.Text;

namespace McAuthz.Requirements {
#if DEBUG
    public class ClaimExpression : ClaimRequirement {
        public new Type ValueType { get => typeof(Func<string, bool>); }

        public ClaimExpression() {


        }

        private Dictionary<Type, dynamic> _expressionCache = new Dictionary<Type, dynamic>();
        public Func<T, bool> GetValue<T> () {
            dynamic funcValue;
            if (_expressionCache.TryGetValue(typeof(T), out funcValue)) {
                return (Func<T, bool>)funcValue;
            }

            var func = new McRule.ExpressionRule((typeof(T).Name, ClaimName, ClaimValue));
            var expr = func.GetPredicateExpression<T>() ?? McRule.PredicateBuilder.False<T>();
            _expressionCache.Add(typeof(T), expr.Compile());
            return expr.Compile();
        }
    }
#endif
}
