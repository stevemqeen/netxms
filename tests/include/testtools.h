#ifndef _testtools_h_
#define _testtools_h_

/**
 * Assert failure
 */
#define Assert(c) do { if (!(c)) { _tprintf(_T("FAIL\nAssert failed at %hs:%d\n"), __FILE__, __LINE__); exit(1); } } while(0)

/**
 * Assert that two values are equal
 */
#define AssertEquals(x, y) Assert((x) == (y))

/**
 * Assert that value is TRUE
 */
#define AssertTrue(x) Assert((x))

/**
 * Assert that value is FALSE
 */
#define AssertFalse(x) Assert(!(x))

/**
 * Assert that value is NULL
 */
#define AssertNull(x) Assert((x) == NULL)

/**
 * Assert that value is not NULL
 */
#define AssertNotNull(x) Assert((x) != NULL)

/**
 * Show test start mark
 */
inline void StartTest(const TCHAR *name)
{
   TCHAR filler[80];
   int l = 60 - (int)_tcslen(name);
   if (l > 0)
   {
      for(int i = 0; i < l; i++)
         filler[i] = _T('.');
      filler[l] = 0;
   }
   else
   {
      filler[0] = 0;
   }
   _tprintf(_T("%s %s "), name, filler);
   fflush(stdout);
}

/**
 * Show test end
 */
inline void EndTest()
{
   _tprintf(_T("OK\n"));
}

/**
 * Show test end with timimg
 */
inline void EndTest(INT64 ms)
{
   _tprintf(_T("%d ms\n"), (int)ms);
}

#endif
