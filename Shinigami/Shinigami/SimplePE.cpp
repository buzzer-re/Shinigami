#include "SimplePE.h"

SimplePE::SimplePE(const std::wstring& Path)
	: Path(Path)
{
	Valid = Load();
}

BOOL SimplePE::Load()
{
	return 0;
}


BOOL SimplePE::IsDLL() const
{
	return TRUE;
}
