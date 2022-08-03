using System;
using System.Collections.Generic;

namespace Bitmessage.Storage
{
    /// <summary>
    /// Compares indexes according to the hash, disregarding the database offset.
    /// </summary>
    internal class DbIndexComparer : IEqualityComparer<DbIndex>
    {
        public bool Equals(DbIndex x, DbIndex y)
        {
            if(x is null)
            {
                return y is null;
            }
            if(y is null)
            {
                return x is null;
            }
            return x.ReferencesSameObject(y);
        }

        public int GetHashCode(DbIndex obj)
        {
            if (obj is null)
            {
                throw new ArgumentNullException(nameof(obj));
            }

            return obj.GetHashCode();
        }
    }
}
